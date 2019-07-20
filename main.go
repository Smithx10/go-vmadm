package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Println("vim-go")
}

type VM struct {
	Alias                      string            `json:"alias"`
	ArchiveOnDelete            bool              `json:"archive_on_delete"`
	AutoBoot                   bool              `json:"auto_boot"`
	BillingID                  string            `json:"billing_id"`
	BhyveExtraOpts             string            `json:"bhyve_extra_opts"`
	Boot                       string            `json:"boot"`
	BootTimestamp              time.RFC3339      `json:"boot_time_stamp"`
	Bootrom                    string            `json:"bootrom"`
	Brand                      string            `json:"brand"`
	CPUCap                     int               `json:"cpu_cap"`
	CPUShares                  int               `json:"cpu_shares"`
	CPUType                    string            `json:"cpu_type"`
	CreateTimestamp            time.RFC3339      `json:"create_timestamp"`
	ServerUUID                 string            `json:"server_uuid"`
	CustomerMetadata           map[string]string `json:"customer_metadata"`
	Datasets                   string            `json:"datasets"`
	DelegateDataset            bool              `json:"delegate_dataset"`
	Disks                      []Disk            `json:"disks"`
	DiskDriver                 string            `json:"disk_driver"`
	DoNotInventory             bool              `json:"do_not_inventory"`
	DNSDomain                  string            `json:"dns_domain"`
	FileSystems                []FileSystem      `json:"filesystems"`
	FirewallEnabled            bool              `json:"firewall_enabled"`
	FlexibleDiskSize           int               `json:"flexible_disk_size"`
	FSAllowed                  string            `json:"fs_allowed"`
	Hostname                   string            `json:"hostname"`
	HVM                        bool              `json:"hvm"`
	ImageUUID                  `json:"image_uuid"`
	InternalMetadata           map[string]string `json:"internal_metadata"`
	InternalMetadataNamespaces []string          `json:"internal_metadata_namespaces"`
	IndestructibleDelegated    bool              `json:"indestructible_delegated"`
	IndestructibleZoneRoot     string            `json:"indestructible_zoneroot"`
	KernelVersion              string            `json:"kernel_version"`
	LimitPriv                  []string          `json:"limit_priv"`
	MaintainResolvers          bool              `json:"maintain_resolvers"`
	MaxLockedMemory            int               `json:"max_locked_memory"`
	MaxLWPS                    int               `json:"max_lwps"`
	MaxPhysicalMemory          int               `json:"max_physical_memory"`
	MaxSwap                    int               `json:"max_swap"`
	MdataExecTimeout           int               `json:"mdata_exec_timeout"`
	NICs                       []NIC             `json:"nics"`
	NICDriver                  string            `json:"nic_driver"`
	NoWait                     bool              `json:"nowait"`
	OwnerUUID                  string            `json:"owner_uuid"`
	PackageName                string            `json:"package_name"`
	PackageVersion             string            `json:"package_version"`
	PID                        int               `json:"pid"`
	QEMUOpts                   []string          `json:"qemu_opts"`
	QEMUExtraOpts              []string          `json:"qemu_extra_opts"`
	Quota                      int               `json:"quota"`
	RAM                        int               `json:"ram"`
	Resolvers                  []string          `json:"resolvers"`
	Routes                     map[string]string `json:"routes"`
	Snapshots                  []string          `json:"snapshots"`
	SpiceOpts                  string            `json:"spice_opts"`
	SpicePassword              string            `json:"spice_password"`
	SpicePort                  string            `json:"spice_port"`
	State                      string            `json:"state"`
	TMPFS                      string            `json:"tmpfs"`
	TransitionExpire           time.Time         `json:"transition_expire"`
	TransitionTo               string            `json:"transition_to"`
	Type                       string            `json:"type"`
	UUID                       string            `json:"uuid"`
	VCPUs                      int               `json:"vcpus"`
	VGA                        string            `json:"vga"`
	VirtIOTXBurst              int               `json:"virtio_txburst"`
	VirtIOTXTimer              int               `json:"virtio_txtimer"`
	VNCPassword                string            `json:"vnc_password"`
	VNCPort                    int               `json:"vnc_port"`
	ZFSDataCompression         string            `json:"zfs_data_compression"`
	ZFSDataRecSize             int               `json:"zfs_data_recsize"`
	ZFSFilesystemLimit         int               `json:"zfs_filesystem_limit"`
	ZFSIOPriority              int               `json:"zfs_io_priority"`
	ZFSRootCompression         string            `json:"zfs_root_compression"`
	ZFSRootRecSize             int               `json:"zfs_root_recsize"`
	ZFSSnapshotLimit           int               `json:"zfs_snapshot_limit"`
	ZLogMaxSize                int               `json:"zlog_max_size"`
	ZLogMode                   string            `json:"zlog_mode"`
	ZoneState                  string            `json:"zone_state"`
	ZonePath                   string            `json:"zonepath"`
	ZoneName                   string            `json:"zonename"`
	ZoneDID                    int               `json:"zonedid"`
	ZoneID                     int               `json:"zoneid"`
	ZPool                      string            `json:"zpool"`
}

type Disk struct {
	BlockSize      int    `json:"block_size"`
	Boot           bool   `json:"boot"`
	Compression    string `json:"compression"`
	NoCreate       bool   `json:"nocreate"`
	ImageName      string `json:"image_name"`
	ImageSize      int    `json:"image_size"`
	ImageUUID      string `json:"image_uuid"`
	PCISlot        string `json:"pci_slot"`
	RefReservation string `json:"refreservation"`
	Size           int    `json:"size"`
	Media          string `json:"media"`
	Model          string `json:"model"`
	ZPool          string `json:"zpool"`
}

type FileSystem struct {
	Type    string   `json:"type"`
	Source  string   `json:"source"`
	Target  string   `json:"target"`
	Raw     string   `json:"raw"`
	Options []string `json:"options"`
}

type NIC struct {
	AllowIPSpoofing        bool     `json:"allow_ip_spoofing"`
	AllowMACSpoofing       bool     `json:"allow_mac_spoofing"`
	AllowRestrictedTraffic bool     `json:"allow_restricted_traffic"`
	AllowUnfilteredPromisc bool     `json:"allow_unfiltered_promisc"`
	BlockedOutgoingPorts   []int    `json:"blocked_outgoing_ports"`
	AllowedIPs             []string `json:"allowed_ips"`
	AllowedDHCPCIDs        []string `json:"allowed_dhcp_cids"`
	DHCPServer             bool     `json:"dhcp_server"`
	Gateway                string   `json:"gateway"`
	Gateways               []string `json:"gateways"`
	Interface              string   `json:"interface"`
	IP                     string   `json:"ip"`
	IPs                    []string `json:"ips"`
	MAC                    string   `json:"mac"`
	Model                  string   `json:"model"`
	MTU                    int      `json:"mtu"`
	Netmask                string   `json:"netmask"`
	NetworkUUID            string   `json:"network_uuid"`
	NICTag                 string   `json:"nic_tag"`
	Primary                bool     `json:"primary"`
	VLANIDs                int      `json:"vlan_ids"`
	VRRPPrimaryIP          string   `json:"vrrp_primary_ip"`
	VRRPVRID               int      `json:"vrrp_vrid"`
}
