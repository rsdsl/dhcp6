//! Minimal DHCPv6 client implementation with Rapid Commit support
//! and auto-rebinding after link disruption.

use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};
use tokio::time::Interval;

/// Possible states of the client.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Dhcp6cState {
    #[default]
    Starting, // Lower layer down, no restart timer.
    Soliciting, // Soliciting a new lease.
    Requesting, // Advertise received, requesting the lease (no Rapid Commit).
    Renewing,   // Renewing the active lease.
    Rebinding,  // Rebinding the active lease.
    Rerouting,  // Rebinding the lease after link disruption (prefix not valid).
    Opened,     // Lower layer up, idle, lease valid, no renewal or rebind needed.
}

/// List of valid packet types for this implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketType {
    Solicit,
    Advertise,
    Request,
    Reply,
    Renew,
    Rebind,
}

/// A DHCPv6 packet.
#[derive(Debug)]
pub struct Packet {
    pub ty: PacketType,
    pub success: bool,
}

/// Information on the various timers of a lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    pub timestamp: Instant,
    pub t1: Duration,
    pub t2: Duration,
    pub valid_lifetime: Duration,
}

impl Lease {
    /// Reports whether a renewal is needed.
    pub fn needs_renewal(&self) -> bool {
        !self.has_expired()
            && !self.needs_rebind()
            && Instant::now().duration_since(self.timestamp) > self.t1
    }

    /// Reports whether a rebind is needed.
    pub fn needs_rebind(&self) -> bool {
        !self.has_expired() && Instant::now().duration_since(self.timestamp) > self.t2
    }

    /// Reports whether the lease has expired.
    pub fn has_expired(&self) -> bool {
        Instant::now().duration_since(self.timestamp) > self.valid_lifetime
    }

    /// Waits until a renewal is needed.
    pub async fn wait_renew(&self) {
        tokio::time::sleep_until((self.timestamp + self.t1).into()).await
    }

    /// Waits until a rebind is needed.
    pub async fn wait_rebind(&self) {
        tokio::time::sleep_until((self.timestamp + self.t2).into()).await
    }

    /// Waits until the lease expires.
    pub async fn wait_expire(&self) {
        tokio::time::sleep_until((self.timestamp + self.valid_lifetime).into()).await
    }
}

/// A simple DHCPv6-PD client that supports Rapid Commit and auto-rebinding
/// after link disruption.
#[derive(Debug)]
pub struct Dhcp6c {
    state: Dhcp6cState,
    lease: Option<Lease>,

    restart_timer: Interval,
    restart_counter: u32,

    max_request: u32,

    output_tx: mpsc::UnboundedSender<Packet>,
    output_rx: mpsc::UnboundedReceiver<Packet>,

    upper_status_tx: watch::Sender<bool>,
    upper_status_rx: watch::Receiver<bool>,
}

impl Dhcp6c {
    /// Creates a new `Dhcp6c`.
    ///
    /// You **must** start calling the [`Dhcp6c::to_send`] method
    /// before calling the [`Dhcp6c::up`] method
    /// and keep calling it until [`Dhcp6c::down`] has been issued.
    ///
    /// # Arguments
    ///
    /// * `lease` - The existing [`Lease`] if one exists.
    /// * `restart_interval` - The retransmission interval, default is 6 seconds.
    /// * `max_request` - The maximum number of Request or Rebind (reroute) attempts, default is 10.
    pub fn new(
        lease: Option<Lease>,
        restart_interval: Option<Duration>,
        max_request: Option<u32>,
    ) -> Self {
        let restart_timer =
            tokio::time::interval(restart_interval.unwrap_or(Duration::from_secs(6)));
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let (upper_status_tx, upper_status_rx) = watch::channel(false);

        Self {
            state: Dhcp6cState::default(),
            lease,

            restart_timer,      // Needs to be reset by some events.
            restart_counter: 0, // Needs to be initialized by some events.

            max_request: max_request.unwrap_or(10),

            output_tx,
            output_rx,

            upper_status_tx,
            upper_status_rx,
        }
    }

    /// Waits for and returns the next packet to send.
    pub async fn to_send(&mut self) -> Packet {
        loop {
            tokio::select! {
                packet = self.output_rx.recv() => return packet.expect("output channel is closed"),
                _ = self.restart_timer.tick() => if self.restart_counter > 0 { // TO+ event
                    if let Some(packet) = self.timeout_positive() { return packet; }
                } else { // TO- event
                    if let Some(packet) = self.timeout_negative() { return packet; }
                }
            }
        }
    }

    /// Feeds a packet into the state machine for processing.
    /// Can trigger the RA, RR+ or RR- events.
    pub fn from_recv(&mut self, packet: Packet) {
        match packet.ty {
            PacketType::Solicit | PacketType::Request | PacketType::Renew | PacketType::Rebind => {} // illegal
            PacketType::Advertise => self.ra(),
            PacketType::Reply => self.rr(),
        }
    }

    /// Signals to the state machine that the lower layer is now up.
    /// This is equivalent to the Up event.
    pub fn up(&mut self) {
        match self.lease {
            Some(ref lease) if !lease.has_expired() => self.up_positive(),
            _ => self.up_negative(),
        }
    }

    fn up_positive(&mut self) {
        if self.state == Dhcp6cState::Starting {
            self.restart_timer.reset();
            self.restart_counter = self.max_request;

            self.output_tx
                .send(Packet {
                    ty: PacketType::Rebind,
                    success: false,
                })
                .expect("output channel is closed");
            self.restart_counter -= 1;

            self.state = Dhcp6cState::Rerouting;
        }
    }

    fn up_negative(&mut self) {
        if self.state == Dhcp6cState::Starting {
            self.output_tx
                .send(Packet {
                    ty: PacketType::Solicit,
                    success: false,
                })
                .expect("output channel is closed");

            self.state = Dhcp6cState::Soliciting;
        }
    }

    /// Signals to the state machine that the lower layer is now down.
    /// This is equivalent to the Down event.
    pub fn down(&mut self) {
        match self.state {
            Dhcp6cState::Starting => {} // illegal
            Dhcp6cState::Soliciting | Dhcp6cState::Requesting | Dhcp6cState::Rerouting => {
                self.state = Dhcp6cState::Starting
            }
            Dhcp6cState::Renewing | Dhcp6cState::Rebinding | Dhcp6cState::Opened => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.state = Dhcp6cState::Starting;
            }
        }
    }

    /// Returns a watch channel receiver that can be used to monitor whether
    /// the `Dhcp6c` has a valid and routed prefix.
    /// This is equivalent to the `Renewing`, `Rebinding` and `Opened` states.
    pub fn opened(&self) -> watch::Receiver<bool> {
        self.upper_status_rx.clone()
    }

    fn timeout_positive(&mut self) -> Option<Packet> {
        match self.state {
            Dhcp6cState::Starting | Dhcp6cState::Opened => None, // illegal
            Dhcp6cState::Soliciting => Some(Packet {
                ty: PacketType::Solicit,
                success: false,
            }),
            Dhcp6cState::Requesting => {
                self.restart_counter -= 1;
                Some(Packet {
                    ty: PacketType::Request,
                    success: false,
                })
            }
            Dhcp6cState::Renewing => Some(Packet {
                ty: PacketType::Renew,
                success: false,
            }),
            Dhcp6cState::Rebinding => Some(Packet {
                ty: PacketType::Rebind,
                success: false,
            }),
            Dhcp6cState::Rerouting => {
                self.restart_counter -= 1;
                Some(Packet {
                    ty: PacketType::Rebind,
                    success: false,
                })
            }
        }
    }

    fn timeout_negative(&mut self) -> Option<Packet> {
        match self.state {
            Dhcp6cState::Starting | Dhcp6cState::Opened => None, // illegal
            Dhcp6cState::Soliciting => Some(Packet {
                ty: PacketType::Solicit,
                success: false,
            }),
            Dhcp6cState::Requesting => {
                self.state = Dhcp6cState::Soliciting;
                Some(Packet {
                    ty: PacketType::Solicit,
                    success: false,
                })
            }
            Dhcp6cState::Renewing => Some(Packet {
                ty: PacketType::Renew,
                success: false,
            }),
            Dhcp6cState::Rebinding => Some(Packet {
                ty: PacketType::Rebind,
                success: false,
            }),
            Dhcp6cState::Rerouting => {
                self.state = Dhcp6cState::Soliciting;
                Some(Packet {
                    ty: PacketType::Solicit,
                    success: false,
                })
            }
        }
    }

    fn ra(&mut self) {
        if self.state == Dhcp6cState::Soliciting {
            self.restart_timer.reset();
            self.restart_counter = self.max_request;

            self.output_tx
                .send(Packet {
                    ty: PacketType::Request,
                    success: false,
                })
                .expect("output channel is closed");
            self.restart_counter -= 1;

            self.state = Dhcp6cState::Requesting;
        }
    }

    fn rr(&mut self) {
        match self.state {
            Dhcp6cState::Starting | Dhcp6cState::Opened => {} // illegal
            Dhcp6cState::Soliciting | Dhcp6cState::Requesting | Dhcp6cState::Rerouting => {
                self.upper_status_tx
                    .send(true)
                    .expect("upper status channel is closed");

                self.state = Dhcp6cState::Opened;
            }
            Dhcp6cState::Renewing | Dhcp6cState::Rebinding => self.state = Dhcp6cState::Opened,
        }
    }
}
