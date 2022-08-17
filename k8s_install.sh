#!/bin/bash


#dir=/root/kubernetes


#需要创建目录 /data/harbor /data /var/log/harbor


MIP=0
NIP=0
SSH_P='22'
DATADIR='/data'
DOCKER_IP='172.62.0.1/26'
SVC_IP='172.61.0.0/16'
POD_IP='172.63.0.0/16'



#传递参数
while getopts "m:w:" option
do 
  case $option in
m)
            MIP=$OPTARG
echo "MASTER_IP IS: $MIP";;


w)
            NIP=$OPTARG
echo "NODE_IP IS: $NIP";;
esac
done


#获取节点ip列表
if [[ $NIP != 0 ]];then
    IPS="$MIP $NIP"
else
    IPS="$MIP"
fi


if [[ $MIP == 0 ]] ;then
echo "master节点参数为空，执行失败"
exit
fi


IX=0
for i in $MIP
do
let IX++
    if [[ $IX == 1 ]];then
        IP1=$i
fi
done





####需要是root 用户 

if test "`id -u`" -ne 0
    then 
echo "You need to run this script as root!" 
exit 0
fi



#解压安装包
c_dir=`pwd`

echo 'unzip install pkg start'
ls ~/kubernetes > /dev/null 2>&1
if [ $? != 0 ];then
dat=`date +%F-%H-%M`
tardir=$c_dir/kubernetes-$dat
mkdir $tardir
rm -rf ~/kubernetes
ln -s $tardir ~/kubernetes > /dev/null 2>&1
unzip -d $tardir kubernetes.zip
echo 'unzip install pkg done'
else
echo '已经存在解压过的包，将直接使用'
fi






######################################################
#设置ssh no check hosts
grep 'StrictHostKeyChecking no' /etc/ssh/ssh_config > /dev/null
if [[ $? != 0 ]];then
echo '设置ssh no check hosts'
echo -e '\nStrictHostKeyChecking no' >> /etc/ssh/ssh_config
fi
#准许root登录
grep 'PermitRootLogin yes' /etc/ssh/sshd_config
if [[ $? != 0 ]];then
echo '设置允许root登录'
sed -i s/'PermitRootLogin no'/'PermitRootLogin yes'/g /etc/ssh/sshd_config
systemctl restart sshd
fi


#准许tcpforward登录
grep 'AllowTcpForwarding yes' /etc/ssh/sshd_config
if [[ $? != 0 ]];then
echo '设置ssh AllowTcpForwarding'
echo -e '\nAllowTcpForwarding yes' >> /etc/ssh/sshd_config
fi



#set ssh trust file
echo "+++++++++++++ set ssh trust file++++++++++++++++++++"
ls /root/.ssh/id_rsa > /dev/null 2>&1
if [[ $? != 0 ]];then
ssh-keygen -t rsa -P '' -f ~/.ssh/id_rsa
ls /root/.ssh/authorized_keys
if [[ $? != 0 ]];then
touch ~/.ssh/authorized_keys
fi
chmod 600 ~/.ssh/authorized_keys
fi


cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys


###ssh 检测######
echo "+++++++++++++ check node ssh ++++++++++++++++++++"
for hi in $IPS
do
ssh -p $SSH_P $hi exit > /dev/null 2>&1
    if [ $? != 0 ];then
echo '------>ssh check failed<---------'
exit 1
fi
done



#时间同步
#!/bin/bash
for i in $IPS;do
  if [ -e /etc/chrony.conf ];then
ssh -p $SSH_P $i "cp /etc/chrony.conf{,-bak}"
cat >> /etc/chrony.conf <<EOF
# Use public servers from the pool.ntp.org project.
# Please consider joining the pool (http://www.pool.ntp.org/join.html).
#server 0.centos.pool.ntp.org iburst
#server 1.centos.pool.ntp.org iburst
#server 2.centos.pool.ntp.org iburst
#server 3.centos.pool.ntp.org iburst
server ntp.aliyun.com iburst
server ntp1.aliyun.com iburst
server ntp2.aliyun.com iburst


driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony


EOF


ssh -p $SSH_P $i "systemctl enable chronyd && systemctl restart chronyd" 
  else
echo "time is not sync, please check node time or install chronyd"
exit
fi
done






#安装ipvs,ipset,ipvsadm,conntrack-tools
#ipvsadm ipset conntrack-tools 安装
for i in $IPS;do
ssh -p $SSH_P $i 'mkdir /root/rpm'
scp -p -P $SSH_P /root/kubernetes/rpm/* $i:/root/rpm
# ssh -p $SSH_P $i "for i in `ls /root/rpm|uniq`;do rpm -vi $i --force --nodeps;done"
ssh -p $SSH_P $i "rpm -vi /root/rpm/conntrack-tools-1.4.4-7.el7.x86_64.rpm --force --nodeps"
ssh -p $SSH_P $i "rpm -vi /root/rpm/ipset-7.1-1.el7.x86_64.rpm --force --nodeps"
ssh -p $SSH_P $i "rpm -vi /root/rpm/ipvsadm-1.27-8.el7.x86_64.rpm --force --nodeps"
ssh -p $SSH_P $i "rpm -vi /root/rpm/libseccomp-2.5.1-1.el8.x86_64.rpm --force --nodeps"
ssh -p $SSH_P $i "rpm -vi /root/rpm/socat-1.7.3.2-2.el7.x86_64.rpm --force --nodeps"


cat >>/etc/sysconfig/modules/ipvs.modules<<EOF
#!/bin/bash
modprobe -- ip_vs
modprobe -- ip_vs_rr
modprobe -- ip_vs_wrr
modprobe -- ip_vs_sh
modprobe -- nf_conntrack
EOF


scp -p -P $SSH_P /etc/sysconfig/modules/ipvs.modules $i:/etc/sysconfig/modules/ipvs.modules
ssh -p $SSH_P $i "chmod +x /etc/sysconfig/modules/ipvs.modules && bash /etc/sysconfig/modules/ipvs.modules && lsmod | grep -e ip_vs -e nf_conntrack"


done



init_system() {
for i in $IPS;do
  #关闭selinux
ssh -p $SSH_P $i "sed -i '/SELINUX/s/enforcing/disabled/' /etc/selinux/config"
ssh -p $SSH_P $i "setenforce 0"
  
  ## 关闭selinux
ssh -p $SSH_P $i "swapoff -a && sysctl -w vm.swappiness=0"
ssh -p $SSH_P $i "sed -ri '/^[^#]*swap/s@^@#@' /etc/fstab"
  
  #关闭firewalld,iptables
ssh -p $SSH_P $i "systemctl stop firewalld && systemctl disable firewalld"
ssh -p $SSH_P $i "systemctl stop iptables && systemctl disable iptables"
  
  [ ! -f /etc/security/limits.conf_bak ] && cp /etc/security/limits.conf{,_bak}
  
cat << EOF >> /etc/security/limits.conf
## Kainstall managed start
root soft nofile 655360
root hard nofile 655360
root soft nproc 655360
root hard nproc 655360
root soft core unlimited
root hard core unlimited
* soft nofile 655360
* hard nofile 655360
* soft nproc 655360
* hard nproc 655360
* soft core unlimited
* hard core unlimited
## Kainstall managed end
EOF


# init sysctl
cat << EOF >> /etc/sysctl.conf
#tcl
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.ip_forward = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 10
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
vm.swappiness = 0
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables=1
fs.inotify.max_user_instances=8192000
fs.inotify.max_user_watches=89100
fs.may_detach_mounts = 1
fs.file-max = 52706963
fs.nr_open = 52706963
net.bridge.bridge-nf-call-arptables = 1
vm.max_map_count=262144
net.core.somaxconn=32768
net.ipv4.tcp_max_tw_buckets=8000
net.netfilter.nf_conntrack_max=1048576
net.nf_conntrack_max=1048576
net.netfilter.nf_conntrack_tcp_timeout_fin_wait=30
net.netfilter.nf_conntrack_tcp_timeout_time_wait=30
net.netfilter.nf_conntrack_tcp_timeout_close_wait=15
net.netfilter.nf_conntrack_tcp_timeout_established=300
net.ipv4.neigh.default.gc_thresh1=128
net.ipv4.neigh.default.gc_thresh2=2048
net.ipv4.neigh.default.gc_thresh3=4096
EOF



#加载br_netfilter modules
cat >>/etc/rc.sysinit<<EOF
#!/bin/bash
for file in /etc/sysconfig/modules/*.modules ; do
[ -x $file ] && $file
done
EOF


ssh -p $SSH_P $i "echo 'modprobe br_netfilter' >/etc/sysconfig/modules/br_netfilter.modules"
ssh -p $SSH_P $i "echo 'modprobe ip_conntrack' >/etc/sysconfig/modules/ip_conntrack.modules"
ssh -p $SSH_P $i "chmod 755 /etc/sysconfig/modules/br_netfilter.modules;chmod 755 /etc/sysconfig/modules/ip_conntrack.modules"
ssh -p $SSH_P $i "echo '1' >> /proc/sys/net/ipv4/ip_forward"
done


}



install_containerd() {
for i in $IPS;do
a=`rpm -qa | grep libseccomp`
  if [[ $a == 'libseccomp-2.3.1-4.el7.x86_64' ]];then 
ssh -p $SSH_P $i 'rpm -e libseccomp-2.3.1-4.el7.x86_64 --nodeps'
ssh -p $SSH_P $i 'rpm -ivh /root/rpm/libseccomp-2.5.1-1.el8.x86_64.rpm'
fi
scp -p -P $SSH_P /root/kubernetes/cri-containerd-cni-1.5.10-linux-amd64.tar.gz $i:/root/cri-containerd-cni-1.5.10-linux-amd64.tar.gz
ssh -p $SSH_P $i 'tar zxvf /root/cri-containerd-cni-1.5.10-linux-amd64.tar.gz -C /'
ssh -p $SSH_P $i 'mkdir /etc/containerd -p'
ssh -p $SSH_P $i 'containerd config default > /etc/containerd/config.toml'
ssh -p $SSH_P $i 'sed -i "s#k8s.gcr.io#registry.aliyuncs.com/google_containers#g" /etc/containerd/config.toml'
ssh -p $SSH_P $i 'sed -i "s/SystemdCgroup = false/SystemdCgroup = true/" /etc/containerd/config.toml'
ssh -p $SSH_P $i 'systemctl enable containerd && systemctl restart containerd'
done
}



#install docker
install_docker() {


for i in $IPS;do
ssh -p $SSH_P $i "mkdir /$DATADIR"
ssh -p $SSH_P $i "mkdir /$DATADIR/docker -p"
ssh -p $SSH_P $i "ln -s /$DATADIR/docker /var/lib/docker"
scp -p -P $SSH_P /root/kubernetes/bin/docker/* $i:/usr/bin
ssh -p $SSH_P $i "chmod 755 /usr/bin/docker*;chmod 755 /usr/bin/container*;chmod 755 /usr/bin/ctr;chmod 755 /usr/bin/runc"
ssh -p $SSH_P $i "cp -f /usr/bin/runc /usr/local/sbin"


ssh -p $SSH_P $i 'ls /usr/lib/systemd/system/docker.service' > /dev/null 2>&1
  if [ $? != 0 ];then
ssh -p $SSH_P $i "
cat <<EOF > /usr/lib/systemd/system/docker.service
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target firewalld.service
Wants=network-online.target


[Service]
Type=notify
ExecStart=/usr/bin/dockerd --bip $DOCKER_IP --log-driver=json-file --log-opt max-size=10m --log-opt max-file=5
ExecReload=/bin/kill -s HUP $MAINPID
LimitNOFILE=infinity
LimitNPROC=infinity
TimeoutStartSec=0
Delegate=yes
KillMode=process
Restart=on-failure
StartLimitBurst=3
StartLimitInterval=60s


[Install]
WantedBy=multi-user.target
EOF
"
fi
cat <<EOF > daemon.json
{ 
  "exec-opts":["native.cgroupdriver=systemd"],
  "insecure-registries": ["reg.mlops.airpot:8090"]
}


EOF
ssh -p $SSH_P $i "systemctl daemon-reload"
ssh -p $SSH_P $i "systemctl enable docker && systemctl restart docker"
ssh -p $SSH_P $i 'mkdir -p /etc/docker'
ssh -p $SSH_P $i 'touch  /etc/docker/daemon.json'
scp -p -P $SSH_P daemon.json $i:/etc/docker/daemon.json
ssh -p $SSH_P $i "systemctl daemon-reload;systemctl restart docker"
ssh -p $SSH_P $i "docker info > /dev/null 2>&1"
if [ $? != 0 ];then
    echo 'install docker failed plz check it and will exit with in 10s'
    sleep 10
    exit 0
fi

done
}









#设置harbor地址
set_reg_dns(){
# set reg dns
echo 'set pri registry dns'
ssh -p $SSH_P $i 'grep reg.mlops.airpot /etc/hosts' > /dev/null 2>&1
if [[ $? != 0 ]];then
ssh -p $SSH_P $i 'echo '"${IP1} reg.mlops.airpot"' >> /etc/hosts'
fi
}



install_harbor() {
chmod +x /root/kubernetes/bin/docker-compose
cp /root/kubernetes/bin/docker-compose /usr/local/bin/docker-compose



tar -zxf /root/kubernetes/harbor-offline-installer-v2.5.0.tgz
cp /root/kubernetes/harbor/harbor.yml.tmpl /root/kubernetes/harbor/harbor.yml
sed -i "s#reg.mydomain.com#reg.mlops.airpot#g" /root/kubernetes/harbor/harbor.yml
sed -i "s#80#8090#g" /root/kubernetes/harbor/harbor.yml
sed -i "s#data_volume: /data#data_volume: /data/harbor#g" /root/kubernetes/harbor/harbor.yml
sed -i "s#Harbor12345#admin#g" /root/kubernetes/harbor/harbor.yml
sed -i '13,18d' /root/kubernetes/harbor/harbor.yml
bash /root/kubernetes/harbor/install.sh

docker login -uadmin -padmin reg.mlops.airpot:8090 

cat  <<EOF > harbor.service
[Unit]
Description=Harbor
After=docker.service systemd-networkd.service systemd-resolved.service
Requires=docker.service
Documentation=http://github.com/vmware/harbor

[Service]
Type=simple
Restart=on-failure
RestartSec=5
ExecStart=/usr/local/bin/docker-compose -f  /root/kubernetes/harbor/docker-compose.yml up
ExecStop=/usr/local/bin/docker-compose -f /root/kubernetes/harbor/docker-compose.yml down

[Install]
WantedBy=multi-user.target

EOF

mv harbor.service /usr/lib/systemd/system/harbor.service
systemctl enable harbor && systemctl restart harbor
}


echo -e "
         ################################################\n
         #### init_system ####\n
         ################################################
"
init_system




echo -e "
         ################################################\n
         #### install docker ####\n
         ################################################
"
install_docker


#kubectl安装以及上次所需镜像
for m in $MIP;do 
chmod +x /root/kubernetes/bin/kubectl
cp -r /root/kubernetes/bin/kubectl /usr/local/bin/kubectl
scp -p -P $SSH_P /root/kubernetes/bin/kubectl $m:/usr/bin/kubectl
# ssh -p $SSH_P $m 'systemctl enable --now kubectl'
  
  
scp -p -P $SSH_P /root/kubernetes/k8s-1.22.3-images.tar $m:/root/k8s-1.22.3-images.tar
# ssh -p $SSH_P $m 'ctr image import /root/k8s-1.22.3-images.tar'
# ssh -p $SSH_P $i 'docker import /root/k8s-1.22.3-images.tar' #测试
done





echo -e "
         ################################################\n
         #### install containerd ####\n
         ################################################
"
install_containerd
for m in $MIP;do 
ssh -p $SSH_P $m 'ctr image import /root/k8s-1.22.3-images.tar'
done

#harbor dns
for i in $IPS;do
  set_reg_dns
done

echo -e "
         ################################################\n
         #### install harbor ####\n
         ################################################
"
install_harbor



echo -e "
         ################################################\n
         #### kubeadm kubelet ####\n
         ################################################
"
#kubeadm kubelet安装
cat >> kubelet.service<<EOF
[Unit]
 
Description=kubelet: The Kubernetes Node Agent
 
Documentation=https://kubernetes.io/docs/
 
 
[Service]
 
ExecStart=/usr/bin/kubelet
 
Restart=always
 
StartLimitInterval=0
 
RestartSec=10
 
 
[Install]
 
WantedBy=multi-user.target
EOF

chmod 777 kubelet.service


for i in $IPS;do
scp -p -P $SSH_P kubelet.service $i:/etc/systemd/system/kubelet.service
ssh -p $SSH_P $i 'mkdir /root/k8s'
scp -p -P $SSH_P /root/kubernetes/k8s/*  $i:/root/k8s
# ssh -p $SSH_P $i "for i in `ls /root/k8s|uniq`;do rpm -vi $i --force --nodeps;done"
#ssh -p $SSH_P $i  "rpm -iv /root/k8s/conntrack-tools-1.4.4-7.el7.x86_64.rpm --force --nodeps"
ssh -p $SSH_P $i  "rpm -iv /root/k8s/kubeadm-1.22.3-0.x86_64.rpm --force --nodeps"
ssh -p $SSH_P $i  "rpm -iv /root/k8s/kubelet-1.22.3-0.x86_64.rpm --force --nodeps"
ssh -p $SSH_P $i  "rpm -iv /root/k8s/kubernetes-cni-0.8.7-0.x86_64.rpm --force --nodeps"
ssh -p $SSH_P $i  "systemctl enable --now kubelet"
ssh -p $SSH_P $i "cp /etc/sysconfig/kubelet{,-bak}"
ssh -p $SSH_P $i  "echo 'KUBELET_EXTRA_ARGS=--container-runtime=remote --container-runtime-endpoint=/run/containerd/containerd.sock --cgroup-driver=systemd' > /etc/sysconfig/kubelet"
done


# #kubectl安装
# for m in $MIP;do
# scp -p -P $SSH_P /root/kubernetes/bin/kubectl $m:/usr/local/bin/kubectl
# ssh -p $SSH_P $m 'systemctl enable --now kubectl'
# done



#添加kubernetes.conf配置

cat >>kubernetes.conf <<EOF
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.ipv4.ip_forward=1
vm.swappiness=0 # 禁止使用 swap 空间，只有当系统 OOM 时才允许使用它
vm.overcommit_memory=1 # 不检查物理内存是否够用
vm.panic_on_oom=0 # 开启 OOM
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=1048576
fs.file-max=52706963
fs.nr_open=52706963
net.ipv6.conf.all.disable_ipv6=1
net.netfilter.nf_conntrack_max=2310720
EOF
for i in $IPS;do
scp -p -P $SSH_P kubernetes.conf $i:/etc/sysctl.d/kubernetes.conf
ssh -p $SSH_P $i "sysctl -p /etc/sysctl.d/kubernetes.conf"
done





#修改kubelet使用containerd
#sed -i 's#KUBELET_EXTRA_ARGS=#KUBELET_EXTRA_ARGS="--cgroup-driver=systemd --container-runtime=remote --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock"#g' /etc/sysconfig/kubelet



#当前master节点安装kubeadm和master相关依赖组建
#初始化kubeadmin
cat > kubeadm-init.yaml <<EOF
apiVersion: kubeadm.k8s.io/v1beta3
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: abcdef.0123456789abcdef
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: $IP1               #k8s-master001 ip地址
  bindPort: 6443
nodeRegistration:
  criSocket: unix:///var/run/containerd/containerd.sock ## 使用 containerd的Unix socket 地址
  imagePullPolicy: IfNotPresent
  name: $IP1
  taints: null
---
apiServer:
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta3
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controllerManager: {}
dns: {}
etcd:
    local:
      dataDir: /var/lib/etcd
imageRepository: registry.aliyuncs.com/google_containers
kind: ClusterConfiguration
kubernetesVersion: 1.22.3
controlPlaneEndpoint: $IP1:6443        
networking:
  dnsDomain: cluster.local
  serviceSubnet: ${SVC_IP}
  podSubnet: ${POD_IP}
scheduler: {}
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs                                            
---
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 0s
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 0s
    cacheUnauthorizedTTL: 0s
clusterDNS:
- `echo ${SVC_IP/0.0/0.10} |awk -F '/' '{print $1}'`
clusterDomain: cluster.local
cpuManagerReconcilePeriod: 0s
evictionPressureTransitionPeriod: 0s
fileCheckFrequency: 0s
healthzBindAddress: 127.0.0.1
healthzPort: 10248
httpCheckFrequency: 0s
imageMinimumGCAge: 0s
kind: KubeletConfiguration
cgroupDriver: systemd                   
logging: {}
memorySwap: {}
nodeStatusReportFrequency: 0s
nodeStatusUpdateFrequency: 0s
rotateCertificates: true
runtimeRequestTimeout: 0s
shutdownGracePeriod: 0s
shutdownGracePeriodCriticalPods: 0s
staticPodPath: /etc/kubernetes/manifests
streamingConnectionIdleTimeout: 0s
syncFrequency: 0s
volumeStatsAggPeriod: 0s


EOF





#部署k8s
echo "========================================="
echo "===========部署kuernetes================="
kubeadm init --config kubeadm-init.yaml --upload-certs --v=6
#kubeadm init \
#--apiserver-advertise-address=192.168.209.130 \
#--image-repository registry.aliyuncs.com/google_containers \
#--kubernetes-version=v1.22.3 \
#--service-cidr=172.60.0.0/16 \
#--pod-network-cidr=172.61.0.0/16 --v=6

mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config


#删除--port=0配置
cp -r /etc/kubernetes/manifests{,-bak}
sed -i 's/- --port=0/#&/' /etc/kubernetes/manifests/kube-scheduler.yaml
sed -i 's/- --port=0/#&/' /etc/kubernetes/manifests/kube-controller-manager.yaml
systemctl restart kubelet





#部署calico
#echo "====calico========="
# curl https://docs.projectcalico.org/manifests/calico.yaml -O
sed -i 's#192.168.0.0/16#${POD_IP}#g' /root/kubernetes/calico.yaml 
kubectl apply -f /root/kubernetes/calico.yaml



#清理多余文件
for i in $IPS;do
  ssh -p $SSH_P $i "rm -rf /root/{cri-containerd-cni-1.5.10-linux-amd64.tar.gz,k8s-1.22.3-images.tar,k8s,rpm}"
  echo "kubernetes init  done, exit: ctrl + c "
done

