IP Modification Moving Target Defense

# install Pip
sudo apt-get install python-pip


# check OVS version
ovs-vsctl --version

# RYU

# install
git clone git://github.com/osrg/ryu.git
cd ryu
pip install .

# run RyuApp

sudo ryu-manager --verbose /home/adrux/Documents/TFIA/RyuAppScripts/mtd10y60.py

# Mininet

# install
sudo apt-get install mininet

# run Topo
sudo python /home/adrux/Documents/TFIA/MTDTopoScan/mtdtopo10scan.py

# clean Topo
sudo mn -c
