# IP Modification Moving Target Defense

## Setting tools

### Install Pip
sudo apt-get install python-pip

### Check OVS version
ovs-vsctl --version

## RYU

### Install
git clone git://github.com/osrg/ryu.git
cd ryu
pip install .

### Run RyuApp
sudo ryu-manager --verbose /home/adrux/Documents/TFIA/RyuAppScripts/mtd10y60.py

## Mininet

### Install
sudo apt-get install mininet

### Run Topo
sudo python /home/adrux/Documents/TFIA/MTDTopoScan/mtdtopo10scan.py

### Clean Topo
sudo mn -c
