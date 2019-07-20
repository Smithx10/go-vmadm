package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

const (
	vmadmPath = "/usr/sbin/vmadm"
)

func main() {
	//vm, err := VMADMGet(&VMADMGetInput{
	//UUID: "256729f4-9974-49c4-961c-36eb95042ed1",
	//})
	//if err != nil {
	//fmt.Println(err)
	//}

	vms, err := VMADMList(&VMADMListInput{})
	if err != nil {
		fmt.Println(err)
	}

	for _, v := range vms {
		fmt.Println(v.Alias)

	}
}

func wrapError(exitCode error, errorMsg bytes.Buffer) error {
	return fmt.Errorf("ExitCode: %s, ErrorMessage: %s", exitCode, string(errorMsg.Bytes()))
}

func runCommand(cmd *exec.Cmd) (*bytes.Buffer, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return nil, wrapError(err, stderr)
	}

	return &stdout, nil
}

func VMADMGet(input *VMADMGetInput) (*VM, error) {
	cmd := exec.Command("vmadm", "get", input.UUID)
	stdout, err := runCommand(cmd)
	if err != nil {
		return nil, err
	}

	// Deserialize
	var vm VM
	err = json.Unmarshal(stdout.Bytes(), &vm)
	if err != nil {
		return nil, err
	}

	return &vm, nil
}

type VMADMGetInput struct {
	UUID string `json:"uuid"`
}

func VMADMList(input *VMADMListInput) ([]*VM, error) {
	cmd := exec.Command("vmadm", "lookup", "-j")
	stdout, err := runCommand(cmd)
	if err != nil {
		return nil, err
	}

	var vms []*VM
	err = json.Unmarshal(stdout.Bytes(), &vms)
	if err != nil {
		return nil, err
	}

	return vms, nil
}

// TODO Add Filtering
type VMADMListInput struct {
}

type VM struct {
	Alias                      string                 `json:"alias", omitempty"`
	ArchiveOnDelete            bool                   `json:"archive_on_delete", omitempty"`
	AutoBoot                   bool                   `json:"auto_boot", omitempty"`
	BillingID                  string                 `json:"billing_id", omitempty"`
	BhyveExtraOpts             string                 `json:"bhyve_extra_opts", omitempty"`
	Boot                       string                 `json:"boot", omitempty"`
	BootTimestamp              time.Time              `json:"boot_time_stamp", omitempty"`
	Bootrom                    string                 `json:"bootrom", omitempty"`
	Brand                      string                 `json:"brand", omitempty"`
	CPUCap                     int                    `json:"cpu_cap", omitempty"`
	CPUShares                  int                    `json:"cpu_shares", omitempty"`
	CPUType                    string                 `json:"cpu_type", omitempty"`
	CreateTimestamp            time.Time              `json:"create_timestamp", omitempty"`
	ServerUUID                 string                 `json:"server_uuid", omitempty"`
	CustomerMetadata           map[string]interface{} `json:"customer_metadata", omitempty"`
	Datasets                   []string               `json:"datasets", omitempty"`
	DelegateDataset            bool                   `json:"delegate_dataset", omitempty"`
	Disks                      []Disk                 `json:"disks", omitempty"`
	DiskDriver                 string                 `json:"disk_driver", omitempty"`
	DoNotInventory             bool                   `json:"do_not_inventory", omitempty"`
	DNSDomain                  string                 `json:"dns_domain", omitempty"`
	FileSystems                []FileSystem           `json:"filesystems", omitempty"`
	FirewallEnabled            bool                   `json:"firewall_enabled", omitempty"`
	FlexibleDiskSize           int                    `json:"flexible_disk_size", omitempty"`
	FSAllowed                  string                 `json:"fs_allowed", omitempty"`
	Hostname                   string                 `json:"hostname", omitempty"`
	HVM                        bool                   `json:"hvm", omitempty"`
	ImageUUID                  string                 `json:"image_uuid", omitempty"`
	InternalMetadata           map[string]interface{} `json:"internal_metadata", omitempty"`
	InternalMetadataNamespaces []string               `json:"internal_metadata_namespaces", omitempty"`
	IndestructibleDelegated    bool                   `json:"indestructible_delegated", omitempty"`
	IndestructibleZoneRoot     string                 `json:"indestructible_zoneroot", omitempty"`
	KernelVersion              string                 `json:"kernel_version", omitempty"`
	LimitPriv                  string                 `json:"limit_priv", omitempty"`
	MaintainResolvers          bool                   `json:"maintain_resolvers", omitempty"`
	MaxLockedMemory            int                    `json:"max_locked_memory", omitempty"`
	MaxLWPS                    int                    `json:"max_lwps", omitempty"`
	MaxPhysicalMemory          int                    `json:"max_physical_memory", omitempty"`
	MaxSwap                    int                    `json:"max_swap", omitempty"`
	MdataExecTimeout           int                    `json:"mdata_exec_timeout", omitempty"`
	NICs                       []NIC                  `json:"nics", omitempty"`
	NICDriver                  string                 `json:"nic_driver", omitempty"`
	NoWait                     bool                   `json:"nowait", omitempty"`
	OwnerUUID                  string                 `json:"owner_uuid", omitempty"`
	PackageName                string                 `json:"package_name", omitempty"`
	PackageVersion             string                 `json:"package_version", omitempty"`
	PID                        int                    `json:"pid", omitempty"`
	QEMUOpts                   []string               `json:"qemu_opts", omitempty"`
	QEMUExtraOpts              []string               `json:"qemu_extra_opts", omitempty"`
	Quota                      int                    `json:"quota", omitempty"`
	RAM                        int                    `json:"ram", omitempty"`
	Resolvers                  []string               `json:"resolvers", omitempty"`
	Routes                     map[string]string      `json:"routes", omitempty"`
	Snapshots                  []string               `json:"snapshots", omitempty"`
	SpiceOpts                  string                 `json:"spice_opts", omitempty"`
	SpicePassword              string                 `json:"spice_password", omitempty"`
	SpicePort                  string                 `json:"spice_port", omitempty"`
	State                      string                 `json:"state", omitempty"`
	TMPFS                      int                    `json:"tmpfs", omitempty"`
	TransitionExpire           time.Time              `json:"transition_expire", omitempty"`
	TransitionTo               string                 `json:"transition_to", omitempty"`
	Type                       string                 `json:"type", omitempty"`
	UUID                       string                 `json:"uuid", omitempty"`
	VCPUs                      int                    `json:"vcpus", omitempty"`
	VGA                        string                 `json:"vga", omitempty"`
	VirtIOTXBurst              int                    `json:"virtio_txburst", omitempty"`
	VirtIOTXTimer              int                    `json:"virtio_txtimer", omitempty"`
	VNCPassword                string                 `json:"vnc_password", omitempty"`
	VNCPort                    int                    `json:"vnc_port", omitempty"`
	ZFSDataCompression         string                 `json:"zfs_data_compression", omitempty"`
	ZFSDataRecSize             int                    `json:"zfs_data_recsize", omitempty"`
	ZFSFilesystemLimit         int                    `json:"zfs_filesystem_limit", omitempty"`
	ZFSIOPriority              int                    `json:"zfs_io_priority", omitempty"`
	ZFSRootCompression         string                 `json:"zfs_root_compression", omitempty"`
	ZFSRootRecSize             int                    `json:"zfs_root_recsize", omitempty"`
	ZFSSnapshotLimit           int                    `json:"zfs_snapshot_limit", omitempty"`
	ZLogMaxSize                int                    `json:"zlog_max_size", omitempty"`
	ZLogMode                   string                 `json:"zlog_mode", omitempty"`
	ZoneState                  string                 `json:"zone_state", omitempty"`
	ZonePath                   string                 `json:"zonepath", omitempty"`
	ZoneName                   string                 `json:"zonename", omitempty"`
	ZoneDID                    int                    `json:"zonedid", omitempty"`
	ZoneID                     int                    `json:"zoneid", omitempty"`
	ZPool                      string                 `json:"zpool", omitempty"`
}

type Disk struct {
	BlockSize      int    `json:"block_size", omitempty"`
	Boot           bool   `json:"boot", omitempty"`
	Compression    string `json:"compression", omitempty"`
	NoCreate       bool   `json:"nocreate", omitempty"`
	ImageName      string `json:"image_name", omitempty"`
	ImageSize      int    `json:"image_size", omitempty"`
	ImageUUID      string `json:"image_uuid", omitempty"`
	PCISlot        string `json:"pci_slot", omitempty"`
	RefReservation string `json:"refreservation", omitempty"`
	Size           int    `json:"size", omitempty"`
	Media          string `json:"media", omitempty"`
	Model          string `json:"model", omitempty"`
	ZPool          string `json:"zpool", omitempty"`
}

type FileSystem struct {
	Type    string   `json:"type", omitempty"`
	Source  string   `json:"source", omitempty"`
	Target  string   `json:"target", omitempty"`
	Raw     string   `json:"raw", omitempty"`
	Options []string `json:"options", omitempty"`
}

type NIC struct {
	AllowIPSpoofing        bool     `json:"allow_ip_spoofing", omitempty"`
	AllowMACSpoofing       bool     `json:"allow_mac_spoofing", omitempty"`
	AllowRestrictedTraffic bool     `json:"allow_restricted_traffic", omitempty"`
	AllowUnfilteredPromisc bool     `json:"allow_unfiltered_promisc", omitempty"`
	BlockedOutgoingPorts   []int    `json:"blocked_outgoing_ports", omitempty"`
	AllowedIPs             []string `json:"allowed_ips", omitempty"`
	AllowedDHCPCIDs        []string `json:"allowed_dhcp_cids", omitempty"`
	DHCPServer             bool     `json:"dhcp_server", omitempty"`
	Gateway                string   `json:"gateway", omitempty"`
	Gateways               []string `json:"gateways", omitempty"`
	Interface              string   `json:"interface", omitempty"`
	IP                     string   `json:"ip", omitempty"`
	IPs                    []string `json:"ips", omitempty"`
	MAC                    string   `json:"mac", omitempty"`
	Model                  string   `json:"model", omitempty"`
	MTU                    int      `json:"mtu", omitempty"`
	Netmask                string   `json:"netmask", omitempty"`
	NetworkUUID            string   `json:"network_uuid", omitempty"`
	NICTag                 string   `json:"nic_tag", omitempty"`
	Primary                bool     `json:"primary", omitempty"`
	VLANIDs                int      `json:"vlan_ids", omitempty"`
	VRRPPrimaryIP          string   `json:"vrrp_primary_ip", omitempty"`
	VRRPVRID               int      `json:"vrrp_vrid", omitempty"`
}
