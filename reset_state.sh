sudo systemctl disable --now gatekeeper
sudo rm -rf /opt/gatekeeper
sudo rm -rf /etc/systemd/system/gatekeeper.service.d
sudo systemctl daemon-reload
sudo systemctl reset-failed gatekeeper 2>/dev/null

sudo ip addr flush dev ens37
sudo ip link set ens37 down
sudo ip link set ens37 up

