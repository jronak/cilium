// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/idpool"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

const testLocalRouterIP = "169.254.23.0"

func setTestLocalRouterIP(t *testing.T) {
	t.Helper()
	oldV4, oldV6 := option.Config.LocalRouterIPv4, option.Config.LocalRouterIPv6
	option.Config.LocalRouterIPv4, option.Config.LocalRouterIPv6 = testLocalRouterIP, ""
	t.Cleanup(func() {
		option.Config.LocalRouterIPv4, option.Config.LocalRouterIPv6 = oldV4, oldV6
	})
}

func testNodeWithAddrs(name string, addrs ...nodeTypes.Address) *nodeTypes.Node {
	return &nodeTypes.Node{Name: name, Cluster: "cluster-1", IPAddresses: addrs}
}

func testAddr(typ addressing.AddressType, ip string) nodeTypes.Address {
	return nodeTypes.Address{Type: typ, IP: iputil.AddrFrom(netip.MustParseAddr(ip))}
}

type seededNodeMap struct {
	entries map[netip.Addr]nodemap.NodeValueV2
}

func (m *seededNodeMap) Update(ip netip.Addr, nodeID uint16, spi uint8, _ bool) error {
	m.entries[ip] = nodemap.NodeValueV2{NodeID: nodeID, SPI: spi}
	return nil
}

func (m *seededNodeMap) Delete(ip netip.Addr) error {
	delete(m.entries, ip)
	return nil
}

func (m *seededNodeMap) IterateWithCallback(cb nodemap.NodeIterateCallbackV2) error {
	for ip, val := range m.entries {
		key := &nodemap.NodeKey{Family: bpf.EndpointKeyIPv4}
		v4 := ip.As4()
		copy(key.IP[:], v4[:])
		cb(key, &val)
	}
	return nil
}

func (m *seededNodeMap) Size() uint32 {
	return nodemap.DefaultMaxEntries
}

func TestNodeIDsIgnoreSharedLocalRouterIP(t *testing.T) {
	setTestLocalRouterIP(t)
	handler, _ := newTestLinuxNodeOps(t)

	nodeA := testNodeWithAddrs("node-a",
		testAddr(addressing.NodeInternalIP, "10.0.0.1"),
		testAddr(addressing.NodeCiliumInternalIP, testLocalRouterIP),
	)
	nodeB := testNodeWithAddrs("node-b",
		testAddr(addressing.NodeInternalIP, "10.0.0.2"),
		testAddr(addressing.NodeCiliumInternalIP, testLocalRouterIP),
	)

	idA, err := handler.allocateIDForNode(nil, nodeA)
	require.NoError(t, err)
	idB, err := handler.allocateIDForNode(nil, nodeB)
	require.NoError(t, err)
	require.NotEqual(t, idA, idB)

	for range 3 {
		_, err = handler.allocateIDForNode(nodeA, nodeA)
		require.NoError(t, err)
		_, err = handler.allocateIDForNode(nodeB, nodeB)
		require.NoError(t, err)
	}
	require.Equal(t, idA, handler.nodeIDsByIPs["10.0.0.1"])
	require.Equal(t, idB, handler.nodeIDsByIPs["10.0.0.2"])
	require.NotContains(t, handler.nodeIDsByIPs, testLocalRouterIP)

	require.NoError(t, handler.deallocateIDForNode(nodeA))
	require.NotContains(t, handler.nodeIDsByIPs, "10.0.0.1")
	require.Equal(t, idB, handler.nodeIDsByIPs["10.0.0.2"])
}

func TestRestoreNodeIDsDropsLocalRouterIP(t *testing.T) {
	setTestLocalRouterIP(t)
	handler, _ := newTestLinuxNodeOps(t)
	nodeMap := &seededNodeMap{entries: map[netip.Addr]nodemap.NodeValueV2{
		netip.MustParseAddr("10.0.0.1"):        {NodeID: 3},
		netip.MustParseAddr(testLocalRouterIP): {NodeID: 3},
	}}
	handler.nodeMap = nodeMap

	handler.RestoreNodeIDs()

	require.Equal(t, uint16(3), handler.nodeIDsByIPs["10.0.0.1"])
	require.NotContains(t, handler.nodeIDsByIPs, testLocalRouterIP)
	require.NotContains(t, nodeMap.entries, netip.MustParseAddr(testLocalRouterIP))
}

func TestNodeIDReturnedWhenLastIPUnmapped(t *testing.T) {
	handler, _ := newTestLinuxNodeOps(t)
	handler.nodeIDs = idpool.NewIDPool(1, 2)

	nodeA := testNodeWithAddrs("node-a",
		testAddr(addressing.NodeInternalIP, "10.0.0.1"),
		testAddr(addressing.NodeInternalIP, "192.0.2.1"),
	)
	nodeBPartial := testNodeWithAddrs("node-b", testAddr(addressing.NodeInternalIP, "10.0.0.2"))
	nodeB := testNodeWithAddrs("node-b",
		testAddr(addressing.NodeInternalIP, "10.0.0.2"),
		testAddr(addressing.NodeInternalIP, "192.0.2.1"),
	)

	_, err := handler.allocateIDForNode(nil, nodeA)
	require.NoError(t, err)
	idB, err := handler.allocateIDForNode(nil, nodeBPartial)
	require.NoError(t, err)

	newIDB, err := handler.allocateIDForNode(nodeBPartial, nodeB)
	require.NoError(t, err)
	require.Equal(t, idB, newIDB)
	require.Equal(t, newIDB, handler.nodeIDsByIPs["10.0.0.2"])
}

func TestNodeIDZeroNeverEntersPool(t *testing.T) {
	handler, _ := newTestLinuxNodeOps(t)
	handler.nodeMap = &seededNodeMap{entries: map[netip.Addr]nodemap.NodeValueV2{
		netip.MustParseAddr("10.0.0.1"): {NodeID: 0},
	}}

	handler.RestoreNodeIDs()
	require.NoError(t, handler.deallocateIDForNode(
		testNodeWithAddrs("node-b", testAddr(addressing.NodeInternalIP, "10.0.0.2"))))

	require.False(t, handler.nodeIDs.Remove(0))
}
