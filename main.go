package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
)

const (
	vmadmPath = "/usr/sbin/vmadm"
)

func main() {
	var v VM

	vm, err := v.Create(&CreateInput{
		Alias:             "Test",
		Brand:             "joyent",
		DelegateDataset:   true,
		ZFSIOPriority:     30,
		Quota:             20,
		ImageUUID:         "c2c31b00-1d60-11e9-9a77-ff9f06554b0f",
		MaxPhysicalMemory: 256,
		NICs: []NIC{
			{
				NICTag: "external",
				IPs: []string{
					"10.45.140.20/24",
				},
				Gateways: []string{
					"10.45.140.1",
				},
				Primary: true,
			},
		},
	})
	if err != nil {
		fmt.Println(vm, err)
	}

	//myvm, err := v.Get(&GetInput{
	//UUID: vm.UUID,
	//})
	//if err != nil {
	//fmt.Println(err)
	//}
	//fmt.Println(myvm.Alias)

	var inst *VM
	vms, err := v.List(&ListInput{})
	if err != nil {
		fmt.Println(err)
	}
	for _, v := range vms {
		if v.Alias == "Test" {
			inst = v
		}
	}
	fmt.Println(inst.Datasets, inst.ZFSFilesystem)

	//err = v.Update(&UpdateInput{
	//UUID: inst.UUID,
	//NICs: []NIC{
	//{
	//NICTag: "external",
	//IPs: []string{
	//"10.45.140.21/24",
	//},
	//UpdateOperation: "add",
	//},
	//{
	//NICTag: "external",
	//MAC:    inst.NICs[0].MAC,
	//IPs: []string{
	//"10.45.140.22/24",
	//},
	//UpdateOperation: "update",
	//},
	//},
	//Quota: 30,
	//})
	//if err != nil {
	//fmt.Println(err)
	//}

	//err = v.Destroy(&DestroyInput{
	//UUID: vm.UUID,
	//})
	//if err != nil {
	//fmt.Println(err)
	//}

	//updated, err := v.Get(&GetInput{
	//UUID: inst.UUID,
	//})
	//if err != nil {
	//fmt.Println(err)
	//}
	//fmt.Printf("%+v, %+v\n", updated.NICs, updated.Quota)

}

func wrapError(exitCode int, errorMsg bytes.Buffer) error {
	var exitCodeString string
	switch exitCode {
	case 1:
		exitCodeString = "An Error Occured"
	case 2:
		exitCodeString = "Invalid Usage"
	}
	return fmt.Errorf("%s: %s", exitCodeString, strings.Split(string(errorMsg.Bytes()), "\n")[0])
}

func runCommand(cmd *exec.Cmd, stdinpipe []byte) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if stdinpipe != nil {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, nil, err
		}
		stdin.Write(stdinpipe)
	}

	if err := cmd.Start(); nil != err {
		log.Fatalf("Error starting program: %s, %s", cmd.Path, err.Error())
	}
	if err := cmd.Wait(); nil != err {
		if exitError, ok := err.(*exec.ExitError); ok {
			return nil, nil, wrapError(exitError.ExitCode(), stderr)
		}
	}

	return stdout.Bytes(), stderr.Bytes(), nil
}

func (v *VM) Create(input *CreateInput) (*VM, error) {
	// Populate a UUID if caller doesn't give one.
	if input.UUID == "" {
		uuid, err := uuid.NewV4()
		if err != nil {
		}
		input.UUID = uuid.String()
	}

	vm, err := json.Marshal(input)
	if err != nil {
		fmt.Println(err)
	}
	cmd := exec.Command("vmadm", "create")
	_, _, err = runCommand(cmd, vm)
	if err != nil {
		return nil, err
	}

	created, err := v.Get(&GetInput{
		UUID: input.UUID,
	})
	if err != nil {
		return nil, err
	}

	return created, nil
}

func (v *VM) Get(input *GetInput) (*VM, error) {
	cmd := exec.Command("vmadm", "get", input.UUID)
	stdout, stderr, err := runCommand(cmd, nil)
	if err != nil {
		fmt.Println(stderr)

		return nil, err
	}
	var vm VM
	err = json.Unmarshal(stdout, &vm)
	if err != nil {
		return nil, err
	}

	return &vm, nil
}

func (v *VM) Update(input *UpdateInput) error {
	fmt.Println(input)
	updateMap := make(map[string]interface{})

	update, err := json.Marshal(input)
	err = json.Unmarshal(update, &updateMap)
	if err != nil {
		fmt.Println(err)
	}

	// See if we are dealing with a Special Object
	if input.NICs != nil {
		var nicsToAdd []NIC
		var nicsToUpdate []NIC
		var nicsToRemove []NIC

		for _, v := range input.NICs {
			switch v.UpdateOperation {
			case "add":
				nicsToAdd = append(nicsToAdd, v)
				break
			case "update":
				nicsToUpdate = append(nicsToUpdate, v)
				break
			case "remove":
				nicsToRemove = append(nicsToRemove, v)
				break
			default:
				return fmt.Errorf("\"NIC.UpdateOperation\" must be set to \"add\", \"update\", or \"remove\"")
			}
		}

		if len(nicsToAdd) > 0 {
			updateMap["add_nics"] = nicsToAdd
		}
		if len(nicsToUpdate) > 0 {
			updateMap["update_nics"] = nicsToUpdate
		}
		if len(nicsToRemove) > 0 {
			updateMap["remove_nics"] = nicsToRemove
		}
	}
	if input.Disks != nil {
		var disksToAdd []Disk
		var disksToUpdate []Disk
		var disksToRemove []Disk

		for _, v := range input.Disks {
			switch v.UpdateOperation {
			case "add":
				disksToAdd = append(disksToAdd, v)
				break
			case "update":
				disksToUpdate = append(disksToUpdate, v)
				break
			case "remove":
				disksToRemove = append(disksToRemove, v)
				break
			default:
				return fmt.Errorf("\"Disk.UpdateOperation\" must be set to \"add\", \"update\", or \"remove\"")
			}
		}

		if len(disksToAdd) > 0 {
			updateMap["add_disks"] = disksToAdd
		}
		if len(disksToUpdate) > 0 {
			updateMap["update_disks"] = disksToUpdate
		}
		if len(disksToRemove) > 0 {
			updateMap["remove_disks"] = disksToRemove
		}
	}

	updateJSON, err := json.Marshal(updateMap)
	fmt.Println(string(updateJSON))
	if err != nil {
		fmt.Println(err)
	}

	cmd := exec.Command("vmadm", "update", input.UUID)
	stdout, stderr, err := runCommand(cmd, updateJSON)
	if err != nil {
		return err
	}
	fmt.Println(string(stdout), string(stderr))

	return nil
}

func (v *VM) Destroy(input *DestroyInput) error {
	cmd := exec.Command("vmadm", "destroy", input.UUID)
	_, _, err := runCommand(cmd, nil)
	if err != nil {
		return err
	}

	return nil
}

// TODO Add Filtering
func (v *VM) List(input *ListInput) ([]*VM, error) {
	cmd := exec.Command("vmadm", "lookup", "-j")
	stdout, stderr, err := runCommand(cmd, nil)
	if err != nil {
		fmt.Println(stderr)
		return nil, err
	}
	var vms []*VM
	err = json.Unmarshal(stdout, &vms)
	if err != nil {
		return nil, err
	}

	return vms, nil
}

type CreateInput struct {
	UUID              string `json:"uuid,omitempty"`
	Brand             string `json:"brand"`
	DelegateDataset   bool   `json:"delegate_dataset,omitempty"`
	ZFSIOPriority     int    `json:"zfs_io_priority,omitempty"`
	Quota             int    `json:"quota,omitempty"`
	ImageUUID         string `json:"image_uuid"`
	MaxPhysicalMemory int    `json:"max_physical_memory,omitempty"`
	Alias             string `json:"alias,ompitempty"`
	NICs              []NIC  `json:"nics,omitempty"`
}

type GetInput struct {
	UUID string `json:"uuid"`
}

type UpdateInput struct {
	UUID  string `json:"uuid"`
	Disks []Disk `json:"disks,omitempty"`
	NICs  []NIC  `json:"nics,omitempty"`
	Quota int    `json:"quota,omitempty"`
}

type DestroyInput struct {
	UUID string `json:"uuid"`
}

type ListInput struct{}

// Vist https://smartos.org/man/1m/vmadm for more specific information about these properties.
// v = vmtype
// l = listable
// c = create
// u = update
// d = default
// pb = possible values
type VM struct {
	Alias                      string                 `json:"alias,omitempty"`                        // v:ANY, l:yes, c:yes, u:yes
	ArchiveOnDelete            bool                   `json:"archive_on_delete,omitempty"`            // v:ANY, l:no, c:yes, u:yes, d: false
	AutoBoot                   bool                   `json:"auto_boot,omitempty"`                    // v:ANY, l:yes, c:yes, u:yes
	BillingID                  string                 `json:"billing_id,omitempty"`                   // v:ANY, l:yes, c:yes, u:yes, d: "00000000-0000-0000-0000-000000000000", pv:(UUID)
	BhyveExtraOpts             string                 `json:"bhyve_extra_opts,omitempty"`             // v:BHYVE, : no, c:yes, u:yes
	Boot                       string                 `json:"boot,omitempty"`                         // v:KVM, l:no, c: yes, u:yes, d: "order=cd"
	BootTimestamp              time.Time              `json:"boot_time_stamp,omitempty"`              // v:ANY, l:yes, c:no, u:no, pv:(ISO 8601 timestamp)
	Bootrom                    string                 `json:"bootrom,omitempty"`                      // v:BHYVE, : no, c:yes, u: yes, d: "bios"
	Brand                      string                 `json:"brand,omitempty"`                        // v:ANY, l:yes, c:yes, u:no, pv: ("joyent"|"joyent-minimal"|"lx"|"kvm"|"bhyve")
	CPUCap                     int                    `json:"cpu_cap,omitempty"`                      // v:ANY, l:yes, c:yes, u:yes(live), pv: (% of single CPUs, 0 for no cap)
	CPUShares                  int                    `json:"cpu_shares,omitempty"`                   // v:ANY, l:yes, c:yes, u:yes(live), d: 100
	CPUType                    string                 `json:"cpu_type,omitempty"`                     // v:KVM, l:yes, c:yes, u:yes, d:"qemu64", pv:("qemu64"|"host")
	CreateTimestamp            time.Time              `json:"c_timestamp,omitempty"`                  // v:ANY, l:yes, c:no, u:no, pv:(ISO 8601 timestamp)
	ServerUUID                 string                 `json:"server_uuid,omitempty"`                  // v:ANY, l:no, c:no, u:no, pv:(UUID)
	CustomerMetadata           map[string]interface{} `json:"customer_metadata,omitempty"`            // v:ANY, l:no, c:yes, u:yes
	Datasets                   []string               `json:"datasets,omitempty"`                     // v:OS, l:no, c:no, u:no
	DelegateDataset            bool                   `json:"delegate_dataset,omitempty"`             // v:OS, l:no, c:yes, u:no, d:false
	Disks                      []Disk                 `json:"disks,omitempty"`                        // v:HVM, l:yes, c:yes, u:yes
	DiskDriver                 string                 `json:"disk_driver,omitempty"`                  // v:KVM, l:no, c:yes, u:yes
	DoNotInventory             bool                   `json:"do_not_inventory,omitempty"`             // v:ANY, l:no, c:yes, u:yes
	DNSDomain                  string                 `json:"dns_domain,omitempty"`                   // v:OS, l:yes, c:yes, u:no
	FileSystems                []FileSystem           `json:"filesystems,omitempty"`                  // v:OS, l:no, c:yes, u:no
	FirewallEnabled            bool                   `json:"firewall_enabled,omitempty"`             // v:OS, l:no, c:yes, u:yes
	FlexibleDiskSize           int                    `json:"flexible_disk_size,omitempty"`           // v:BHYVE, l:yes, c:yes, u:yes(live)
	FSAllowed                  string                 `json:"fs_allowed,omitempty"`                   // v:OS, l:no, c:yes, u:yes(reboot)
	Hostname                   string                 `json:"hostname,omitempty"`                     // v:ANY, l:yes, c:yes, u:yes,d:zonename
	HVM                        bool                   `json:"hvm,omitempty"`                          // v:ANY, l:yes, c:no, u:no
	ImageUUID                  string                 `json:"image_uuid,omitempty"`                   // v:ANY, l:yes, c:yes, u:no, pv:(UUID)
	InternalMetadata           map[string]interface{} `json:"internal_metadata,omitempty"`            // v:ANY, l:no, c:yes, u:yes
	InternalMetadataNamespaces []string               `json:"internal_metadata_namespaces,omitempty"` // v:ANY, l:no, c:yes, u:yes
	IndestructibleDelegated    bool                   `json:"indestructible_delegated,omitempty"`     // v:ANY, l:yes, c:yes, u:yes, d:false
	IndestructibleZoneRoot     string                 `json:"indestructible_zoneroot,omitempty"`      // v:ANY, l:yes, c:yes, u:yes, d:false
	KernelVersion              string                 `json:"kernel_version,omitempty"`               // v:LX, l:no, c:no, u:yes
	LimitPriv                  string                 `json:"limit_priv,omitempty"`                   // v:OS, l:no, c:yes, u:yes, d:"default"
	MaintainResolvers          bool                   `json:"maintain_resolvers,omitempty"`           // v:OS, l:no, c:yes, u:yes, d:false
	MaxLockedMemory            int                    `json:"max_locked_memory,omitempty"`            // v:OS, l:yes, c:yes, u:yes(live), d:max_physical_memory
	MaxLWPS                    int                    `json:"max_lwps,omitempty"`                     // v:OS, l:yes, c:yes, u:yes(live), d:2000
	MaxPhysicalMemory          int                    `json:"max_physical_memory,omitempty"`          // v:ANY, l:yes, c:yes, u:yes(live), d:OS=256,HVM=RAM+1024
	MaxSwap                    int                    `json:"max_swap,omitempty"`                     // v:OS, l:yes, c:yes, u:yes(live), d:max_physical_memory|256(higher)
	MdataExecTimeout           int                    `json:"mdata_exec_timeout,omitempty"`           // v:OS, l:yes, c:yes, u:yes, d:300
	NICs                       []NIC                  `json:"nics,omitempty"`                         // v:HVM, l:yes, c:yes, u:yes
	NICDriver                  string                 `json:"nic_driver,omitempty"`                   // v:KVM, l:no, c:yes, u:yes, pv:"virtio"|"e1000"|"rt18139"
	NoWait                     bool                   `json:"nowait,omitempty"`                       // v:OS, l:no, c:yes, u:no, d:false
	OwnerUUID                  string                 `json:"owner_uuid,omitempty"`                   // v:ANY, l:yes, c:yes, u:yes: d:"00000000-0000-0000-0000-000000000000", pv:(uuid)
	PackageName                string                 `json:"package_name,omitempty"`                 // v:ANY, l:yes, c:yes, u:yes
	PackageVersion             string                 `json:"package_version,omitempty"`              // v:ANY, l:yes, c:yes, u:yes
	PID                        int                    `json:"pid,omitempty"`                          // v:ANY, l:yes, c:no, u:no
	QEMUOpts                   []string               `json:"qemu_opts,omitempty"`                    // v:KVM, l:no, c:yes, u:yes, pv:(space-separated options for qemu)
	QEMUExtraOpts              []string               `json:"qemu_extra_opts,omitempty"`              // v:KVM, l:no, c:yes, u:yes, pv:(space-separated options for qemu)
	Quota                      int                    `json:"quota,omitempty"`                        // v:ANY, l:yes, c:yes, u:yes(live)
	RAM                        int                    `json:"ram,omitempty"`                          // v:HVM, l:yes, c:yes, u:yes, d:256
	Resolvers                  []string               `json:"resolvers,omitempty"`                    // v:ANY|KVM, l:no, c:yes, u:yes
	Routes                     map[string]string      `json:"routes,omitempty"`                       // v:OS, l:no, c:yes, u:yes
	Snapshots                  []string               `json:"snapshots,omitempty"`                    // v:OS|BHYVE, l:no, c:no, u:no
	SpiceOpts                  string                 `json:"spice_opts,omitempty"`                   // v:KVM, l:no, c:yes, u:yes
	SpicePassword              string                 `json:"spice_password,omitempty"`               // v:KVM, l:no, c:yes, u:yes
	SpicePort                  string                 `json:"spice_port,omitempty"`                   // v:KVM, l:no, c:yes, u:yes
	State                      string                 `json:"state,omitempty"`                        // v:ANY, l:yes, c:no, u:no
	TMPFS                      int                    `json:"tmpfs,omitempty"`                        // v:OS, l:yes, c:yes, u:yes, d:max_physical_memory
	TransitionExpire           time.Time              `json:"transition_expire,omitempty"`            // v:KVM, l:no, c:no, u:no
	TransitionTo               string                 `json:"transition_to,omitempty"`                // v:ANY, l:no, c:no, u:no
	Type                       string                 `json:"type,omitempty"`                         // v:ANY, l:yes, c:no, u:no, pv:"OS","LX","KVM","BHYVE"
	UUID                       string                 `json:"uuid,omitempty"`                         // v:ANY, l:yes, c:yes, u:no, d:generated
	VCPUs                      int                    `json:"vcpus,omitempty"`                        // v:HVM, l:yes, c:yes, u:yes(reboot), d:1
	VGA                        string                 `json:"vga,omitempty"`                          // v:KVM, l:no, c:yes, u:yes, d:"std"
	VirtIOTXBurst              int                    `json:"virtio_txburst,omitempty"`               // v:KVM, l:no, c:yes, u:yes, d:128
	VirtIOTXTimer              int                    `json:"virtio_txtimer,omitempty"`               // v:KVM, l:no, c:yes, u:yes, d:200000
	VNCPassword                string                 `json:"vnc_password,omitempty"`                 // v:KVM, l:no, c:yes, u:yes, d:"unset"
	VNCPort                    int                    `json:"vnc_port,omitempty"`                     // v:HVM, l:no, c:yes, u:yes, d:0
	ZFSDataCompression         string                 `json:"zfs_data_compression,omitempty"`         // v:OS, l:yes, c:yes, u:yes, d:off, pv:"on","off","gzip",gzip-N","lz4","lzjb,"zle"
	ZFSDataRecSize             int                    `json:"zfs_data_recsize,omitempty"`             // v:ANY, l:no, c:yes, u:yes, d:131072(128k)
	ZFSFilesystemLimit         int                    `json:"zfs_filesystem_limit,omitempty"`         // v:ANY, l:no, c:yes, u:yes, d:none(no limit)
	ZFSIOPriority              int                    `json:"zfs_io_priority,omitempty"`              // v:ANY, l:yes, c:yes, u:yes(live), d:100
	ZFSRootCompression         string                 `json:"zfs_root_compression,omitempty"`         // v:OS, l:no, c:yes, u:yes, d:off
	ZFSRootRecSize             int                    `json:"zfs_root_recsize,omitempty"`             // v:OS, l:no, c:yes, u:yes, d:131072(128k)
	ZFSSnapshotLimit           int                    `json:"zfs_snapshot_limit,omitempty"`           // v:OS, l:no, c:yes, u:yes, d:none(no limit)
	ZFSFilesystem              string                 `json:"zfs_filesystem,omitempty"` // Not mentioned by vmadm manpage.
	ZLogMaxSize                int                    `json:"zlog_max_size,omitempty"` // v:ANY, l:no, c:yes, u:yes, d:none(no rotation)
	ZLogMode                   string                 `json:"zlog_mode,omitempty"`     // v:ANY, l:no, c:no, u:no 
	ZoneState                  string                 `json:"zone_state,omitempty"`    // v:HVM, l:yes, c:no, u:no
	ZonePath                   string                 `json:"zonepath,omitempty"`      // v:ANY, l:no, c:no, u:no
	ZoneName                   string                 `json:"zonename,omitempty"`      // v:ANY, l:yes, c:yes(OS VMs), u:no, d:UUID
	ZoneDID                    int                    `json:"zonedid,omitempty"`       // v:ANY, l:yes, c:no, u:no
	ZoneID                     int                    `json:"zoneid,omitempty"`        // v:ANY, l:yes, c:no, u:no
	ZPool                      string                 `json:"zpool,omitempty"`         // v:ANY, l:yes, c:yes, u:no, d:zones
}

type Disk struct {
	BlockSize       int    `json:"block_size,omitempty"`       // v:HVM, l:no, c:yes, u:no, d:8192
	Boot            bool   `json:"boot,omitempty"`             // v:HVM, l:yes, c:yes, u:yes, d:no
	Compression     string `json:"compression,omitempty"`      // v:HVM, l:no, c:yes, u:yes, d:off, pv:"on,off,gzip,gzip-N,lz4,lzjb,zle"
	NoCreate        bool   `json:"noc,omitempty"`              // v:HVM, l:no, c:yes, u:no, d:false
	ImageName       string `json:"image_name,omitempty"`       // v:HVM, l:yes, c:yes, u:yes, d:no
	ImageSize       int    `json:"image_size,omitempty"`       // v:HVM, l:yes, c:yes, u:yes, d:no
	ImageUUID       string `json:"image_uuid,omitempty"`       // v:HVM, l:yes, c:yes, u:yes, d:no
	PCISlot         string `json:"pci_slot,omitempty"`         // v:BHYVE, l:yes, c:yes, u:yes, d:no
	RefReservation  string `json:"refreservation,omitempty"`   // v:HVM, l:no, c:yes, u:yes, d:size
	Size            int    `json:"size,omitempty"`             // v:HVM, l:yes, c:yes, u:yes, d:no
	Media           string `json:"media,omitempty"`            // v:HVM, l:yes, c:yes, u:yes, d:disk, pv:"disk","cdrom"
	Model           string `json:"model,omitempty"`            // v:HVM, l:yes, c:yes, u:yes, d:disk_driver, pv:kvm:"virtio","ide","scsi",bhyve:"virtio","ahci"
	ZPool           string `json:"zpool,omitempty"`            // v:HVM, l:yes, c:yes, u:yes, d:zones
	UpdateOperation string `json:"update_operation,omitempty"` // Used During Update to Specify our intent. pv:"add","update","remove"
}

type FileSystem struct {
	Type    string   `json:"type,omitempty"`    // v:OS, l:no, c:yes, u:no
	Source  string   `json:"source,omitempty"`  // v:OS, l:no, c:yes, u:no
	Target  string   `json:"target,omitempty"`  // v:OS, l:no, c:yes, u:no
	Raw     string   `json:"raw,omitempty"`     // v:OS, l:no, c:yes, u:no
	Options []string `json:"options,omitempty"` // v:OS, l:no, c:yes, u:no
	UpdateOperation string `json:"update_operation,omitempty"` // Used During Update to Specify our intent. pv:"add","update","remove"
}

type NIC struct {
	AllowIPSpoofing        bool     `json:"allow_ip_spoofing,omitempty"`        // v: ANY, l: yes, c: yes, u: yes
	AllowMACSpoofing       bool     `json:"allow_mac_spoofing,omitempty"`       // v: ANY, l: yes, c: yes, u: yes
	AllowRestrictedTraffic bool     `json:"allow_restricted_traffic,omitempty"` // v: ANY, l: yes, c: yes, u: yes
	AllowUnfilteredPromisc bool     `json:"allow_unfiltered_promisc,omitempty"` // v: ANY, l: yes, c: yes, u: yes
	BlockedOutgoingPorts   []int    `json:"blocked_outgoing_ports,omitempty"`   // v: ANY, l: yes, c: yes, u: yes
	AllowedIPs             []string `json:"allowed_ips,omitempty"`              // v: ANY, l: yes, c: yes, u: yes
	AllowedDHCPCIDs        []string `json:"allowed_dhcp_cids,omitempty"`        // v: ANY, l: yes, c: yes, u: yes
	DHCPServer             bool     `json:"dhcp_server,omitempty"`              // v: ANY, l: yes, c: yes, u: yes
	Gateway                string   `json:"gateway,omitempty"`                  // v: ANY, l: yes, c: yes, u: yes
	Gateways               []string `json:"gateways,omitempty"`                 // v: ANY, l: yes, c: yes, u: yes
	Interface              string   `json:"interface,omitempty"`                // v: ANY, l: yes, c: yes, u: yes
	IP                     string   `json:"ip,omitempty"`                       // v: ANY, l: yes, c: yes, u: yes
	IPs                    []string `json:"ips,omitempty"`                      // v: ANY, l: yes, c: yes, u: yes
	MAC                    string   `json:"mac,omitempty"`                      // v: ANY, l: yes, c: yes, u: yes
	Model                  string   `json:"model,omitempty"`                    // v: ANY, l: yes, c: yes, u: yes
	MTU                    int      `json:"mtu,omitempty"`                      // v: ANY, l: yes, c: yes, u: yes
	Netmask                string   `json:"netmask,omitempty"`                  // v: ANY, l: yes, c: yes, u: yes
	NetworkUUID            string   `json:"network_uuid,omitempty"`             // v: ANY, l: yes, c: yes, u: yes
	NICTag                 string   `json:"nic_tag,omitempty"`                  // v: ANY, l: yes, c: yes, u: yes
	Primary                bool     `json:"primary,omitempty"`                  // v: ANY, l: yes, c: yes, u: yes
	VLANIDs                int      `json:"vlan_ids,omitempty"`                 // v: ANY, l: yes, c: yes, u: yes
	VRRPPrimaryIP          string   `json:"vrrp_primary_ip,omitempty"`          // v: ANY, l: yes, c: yes, u: yes
	VRRPVRID               int      `json:"vrrp_vrid,omitempty"`                // v: ANY, l: yes, c: yes, u: yes
	UpdateOperation        string   `json:"update_operation,omitempty"`         // Used During Update to Specify our intent. pv:"add","update","remove"
}
