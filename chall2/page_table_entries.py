#!/usr/bin/env python2
import volatility.addrspace as addrspace
import volatility.conf as conf
import volatility.registry as registry
import volatility.utils as utils

registry.PluginImporter()
config = conf.ConfObject()
registry.register_global_options(config, addrspace.BaseAddressSpace)
config.parse_options()
config.update('PROFILE', "Win7SP1x64")
config.update('LOCATION', "file:///tmp/memdump_0x0-0x100000000_20160127-125924.bin")
config.update('dtb', 0x187000)
config.update('kdbg', 0xfffff80003a4d0a0)
config.update('kpcr', 0xfffff80003a4ed00)
addr_space = utils.load_as(config)

# Try to read the page table from DTB
for vaddr, size in addr_space.get_available_pages():
    # Expand kernel virtual addresses
    if vaddr & (1 << 47):
        vaddr |= 0xffff << 48
    phy = addr_space.vtop(vaddr)
    # only output something when the physical address is within 4GB
    if not (phy >> 32):
        print('%16x (%6x) -> %x' % (vaddr, size, phy))
