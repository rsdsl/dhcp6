//! Minimal DHCPv6 client implementation with Rapid Commit support
//! and auto-rebinding after link disruption.

use std::future;

use tokio::sync::{mpsc, watch};
use tokio::time::{Duration, Instant, Interval};

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

/// List of valid packets for this implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    Solicit,
    Advertise,
    Request,
    Reply(Lease, bool),
    Renew,
    Rebind,
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
            && self.t1.as_secs() < u32::MAX.into()
    }

    /// Reports whether a rebind is needed.
    pub fn needs_rebind(&self) -> bool {
        !self.has_expired()
            && Instant::now().duration_since(self.timestamp) > self.t2
            && self.t2.as_secs() < u32::MAX.into()
    }

    /// Reports whether the lease has expired.
    pub fn has_expired(&self) -> bool {
        Instant::now().duration_since(self.timestamp) > self.valid_lifetime
            && self.valid_lifetime.as_secs() < u32::MAX.into()
    }

    /// Waits until a renewal is needed.
    pub async fn wait_renew(&self) {
        if self.t1.as_secs() < u32::MAX.into() {
            tokio::time::sleep_until(self.timestamp + self.t1).await
        } else {
            future::pending().await
        }
    }

    /// Waits until a rebind is needed.
    pub async fn wait_rebind(&self) {
        if self.t2.as_secs() < u32::MAX.into() {
            tokio::time::sleep_until(self.timestamp + self.t2).await
        } else {
            future::pending().await
        }
    }

    /// Waits until the lease expires.
    pub async fn wait_expire(&self) {
        if self.valid_lifetime.as_secs() < u32::MAX.into() {
            tokio::time::sleep_until(self.timestamp + self.valid_lifetime).await
        } else {
            future::pending().await
        }
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
                },
                Some(_) = option_wait_renew(self.lease.as_ref()) => if let Some(packet) = self.t1() { return packet; },
                Some(_) = option_wait_rebind(self.lease.as_ref()) => if let Some(packet) = self.t2() { return packet; },
                Some(_) = option_wait_expire(self.lease.as_ref()) => if let Some(packet) = self.expire() { return packet; },
            }
        }
    }

    /// Feeds a packet into the state machine for processing.
    /// Can trigger the RA, RR+ or RR- events.
    pub fn from_recv(&mut self, packet: Packet) {
        match packet {
            Packet::Solicit | Packet::Request | Packet::Renew | Packet::Rebind => {} // illegal
            Packet::Advertise => self.ra(),
            Packet::Reply(lease, no_binding) => self.rr(lease, no_binding),
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
                .send(Packet::Rebind)
                .expect("output channel is closed");
            self.restart_counter -= 1;

            self.state = Dhcp6cState::Rerouting;
        }
    }

    fn up_negative(&mut self) {
        if self.state == Dhcp6cState::Starting {
            self.restart_timer.reset();

            self.output_tx
                .send(Packet::Solicit)
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

    /// Reports whether the `Dhcp6c` is in the `Soliciting` state.
    pub fn is_soliciting(&self) -> bool {
        self.state == Dhcp6cState::Soliciting
    }

    /// Reports whether the `Dhcp6c` is in the `Rebinding` state.
    pub fn is_rebinding(&self) -> bool {
        self.state == Dhcp6cState::Rebinding
    }

    /// Reports whether the `Dhcp6c` is in the `Rerouting` state.
    pub fn is_rerouting(&self) -> bool {
        self.state == Dhcp6cState::Rerouting
    }

    /// Reports whether the `Dhcp6c` is in a state that accepts new server IDs.
    pub fn accept_new_server_id(&self) -> bool {
        self.is_soliciting() || self.is_rebinding() || self.is_rerouting()
    }

    /// Returns a watch channel receiver that can be used to monitor whether
    /// the `Dhcp6c` has a valid and routed prefix.
    /// This is equivalent to the `Renewing`, `Rebinding` and `Opened` states.
    pub fn opened(&self) -> watch::Receiver<bool> {
        self.upper_status_rx.clone()
    }

    /// Returns a reference to the current internal lease if there is one,
    /// or `None` otherwise.
    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    fn timeout_positive(&mut self) -> Option<Packet> {
        match self.state {
            Dhcp6cState::Starting | Dhcp6cState::Opened => None, // illegal
            Dhcp6cState::Soliciting => Some(Packet::Solicit),
            Dhcp6cState::Requesting => {
                self.restart_counter -= 1;
                Some(Packet::Request)
            }
            Dhcp6cState::Renewing => Some(Packet::Renew),
            Dhcp6cState::Rebinding => Some(Packet::Rebind),
            Dhcp6cState::Rerouting => {
                self.restart_counter -= 1;
                Some(Packet::Rebind)
            }
        }
    }

    fn timeout_negative(&mut self) -> Option<Packet> {
        match self.state {
            Dhcp6cState::Starting | Dhcp6cState::Opened => None, // illegal
            Dhcp6cState::Soliciting => Some(Packet::Solicit),
            Dhcp6cState::Requesting => {
                self.state = Dhcp6cState::Soliciting;
                Some(Packet::Solicit)
            }
            Dhcp6cState::Renewing => Some(Packet::Renew),
            Dhcp6cState::Rebinding => Some(Packet::Rebind),
            Dhcp6cState::Rerouting => {
                self.state = Dhcp6cState::Soliciting;
                Some(Packet::Solicit)
            }
        }
    }

    fn t1(&mut self) -> Option<Packet> {
        match self.state {
            Dhcp6cState::Opened => {
                self.restart_timer.reset();
                self.state = Dhcp6cState::Renewing;

                Some(Packet::Renew)
            }
            _ => None, // illegal
        }
    }

    fn t2(&mut self) -> Option<Packet> {
        match self.state {
            Dhcp6cState::Renewing => {
                self.restart_timer.reset();
                self.state = Dhcp6cState::Rebinding;

                Some(Packet::Rebind)
            }
            _ => None, // illegal
        }
    }

    fn expire(&mut self) -> Option<Packet> {
        match self.state {
            Dhcp6cState::Rebinding => {
                self.restart_timer.reset();

                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.state = Dhcp6cState::Soliciting;

                Some(Packet::Solicit)
            }
            Dhcp6cState::Rerouting => {
                self.restart_timer.reset();
                self.state = Dhcp6cState::Soliciting;

                Some(Packet::Solicit)
            }
            _ => None, // illegal
        }
    }

    fn ra(&mut self) {
        if self.state == Dhcp6cState::Soliciting {
            self.restart_timer.reset();
            self.restart_counter = self.max_request;

            self.output_tx
                .send(Packet::Request)
                .expect("output channel is closed");
            self.restart_counter -= 1;

            self.state = Dhcp6cState::Requesting;
        }
    }

    fn rr(&mut self, mut lease: Lease, no_binding: bool) {
        match self.state {
            Dhcp6cState::Starting | Dhcp6cState::Opened => {} // illegal
            Dhcp6cState::Soliciting
            | Dhcp6cState::Requesting
            | Dhcp6cState::Renewing
            | Dhcp6cState::Rebinding
            | Dhcp6cState::Rerouting => {
                if lease.t1.as_secs() == 0 {
                    lease.t1 = lease.valid_lifetime / 4;
                }

                if lease.t2.as_secs() == 0 {
                    lease.t2 = lease.valid_lifetime / 2;
                }

                // TODO: lft = 0

                if no_binding {
                    self.restart_timer.reset();
                    self.restart_counter = self.max_request;

                    self.output_tx
                        .send(Packet::Request)
                        .expect("output channel is closed");
                    self.restart_counter -= 1;

                    self.state = Dhcp6cState::Requesting;
                } else {
                    self.upper_status_tx
                        .send(true)
                        .expect("upper status channel is closed");

                    self.lease = Some(lease);
                    self.state = Dhcp6cState::Opened;
                }
            }
        }
    }
}

async fn option_wait_renew(lease: Option<&Lease>) -> Option<()> {
    match lease {
        Some(lease) => {
            lease.wait_renew().await;
            Some(())
        }
        None => None,
    }
}

async fn option_wait_rebind(lease: Option<&Lease>) -> Option<()> {
    match lease {
        Some(lease) => {
            lease.wait_rebind().await;
            Some(())
        }
        None => None,
    }
}

async fn option_wait_expire(lease: Option<&Lease>) -> Option<()> {
    match lease {
        Some(lease) => {
            lease.wait_expire().await;
            Some(())
        }
        None => None,
    }
}
