# This is a collection of my Ghidra scripts that I've written while analysing Microsoft security patches (patch diffing)

## search_ghidra_data_types.py

Run this script after you've had Ghidra analyse the target patch file. It will iterate over all available data types, check if the current data type is a structure, and then see if the given string is present there in this structure. If yes, it will print it to the console.

I wrote this script while analysing the Windows Wireless Driver (nWiFi.Sys) patch. I was trying to figure out the second argument, param2 passed to the patched function `Dot11Translate80211ToEthernetNdisPacket()`. This function calls another Windows API, `MmMapLockedPagesSpecifyCache()` and `param2 + 0x28` is passed as the first argument to it. According to this MSDN document[1], at offset 0x28 from param2, it must be a pointer to `_MDL` structure.

After retyping this variable in Ghidra, it looks like this:

```
  pMDL = *(_MDL **)(param_2 + 0x28);
  uVar2 = *(undefined4 *)(param_2 + 0x3c);    // another hint, there is something at offset 0x3c from param2. 
  if ((*(byte *)&pMDL->MdlFlags & 5) == 0) {
    pvMappedPageAddr = (PVOID)MmMapLockedPagesSpecifyCache(pMDL,0,1,0,0,0x40000020);
  }
  else {
    pvMappedPageAddr = pMDL->MappedSystemVa;
  }
```

Also, there's call to another Windows API, `NdisAdvanceNetBufferListDataStart()` where `(param_2 + 0x20` is passed as first argument. According to this MSDN article[2], the first argument to `NdisAdvanceNetBufferListDataStart()` function is a pointer to a previously allocated `NET_BUFFER_LIST` structure. After searching through the Windows Driver Kits installation directory, I noticed that this structure is defined in `./Include/10.0.26100.0/km/ndis/nbl.h`.
                       
I think I had enough hints to figure out what `param2` really is? Is it a structure, pointer, or something else? One of the ways to figure it out is, to go through the call stack in Windows Debugger. I configured my VM for Kernel debugging, connected to it from my host machine, put a breakpoint on the patched function, and then tried to connect to a Mobile HotSpot from the debugee VM.

```
1: kd> k
 # Child-SP          RetAddr               Call Site
00 ffff800b`5270fd58 fffff802`5a503b78     nwifi!Dot11Translate80211ToEthernetNdisPacket
01 ffff800b`5270fd60 fffff802`5a50388d     nwifi!ExtSTAReceiveDataPacket+0x1d8
02 ffff800b`5270fe30 fffff802`5a5014e8     nwifi!ExtSTAReceivePacket+0x1bd
03 ffff800b`5270fe90 fffff802`3e357019     nwifi!Pt6Receive+0x3c8
04 ffff800b`5270ff50 fffff802`3e356a87     ndis!ndisCallReceiveHandler+0xb9
05 ffff800b`5270ffa0 fffff802`3e35d74a     ndis!ndisCallNextDatapathHandler<2,void * __ptr64 & __ptr64,void (__cdecl*& __ptr64)(void * __ptr64,_NET_BUFFER_LIST * __ptr64,unsigned long,unsigned long,unsigned long),void * __ptr64 & __ptr64,_NET_BUFFER_LIST * __ptr64 & __ptr64,unsigned long & __ptr64,unsigned long & __ptr64,unsigned long & __ptr64>+0x3f
06 ffff800b`5270fff0 fffff802`3e357113     ndis!ndisExpandDataPathStack<2,void __cdecl(void * __ptr64,_NET_BUFFER_LIST * __ptr64,unsigned long,unsigned long,unsigned long)>+0xae
07 ffff800b`52710090 fffff802`3e35977b     ndis!ndisInvokeNextReceiveHandler+0xdb
08 ffff800b`527100f0 fffff802`41ee5ffb     ndis!NdisFIndicateReceiveNetBufferLists+0x350fb
09 ffff800b`527101a0 fffff802`3e357019     vwififlt!FilterReceiveNetBufferLists+0xdb
0a ffff800b`52710200 fffff802`3e356a87     ndis!ndisCallReceiveHandler+0xb9
0b ffff800b`52710250 fffff802`3e35d74a     ndis!ndisCallNextDatapathHandler<2,void * __ptr64 & __ptr64,void (__cdecl*& __ptr64)(void * __ptr64,_NET_BUFFER_LIST * __ptr64,unsigned long,unsigned long,unsigned long),void * __ptr64 & __ptr64,_NET_BUFFER_LIST * __ptr64 & __ptr64,unsigned long & __ptr64,unsigned long & __ptr64,unsigned long & __ptr64>+0x3f
0c ffff800b`527102a0 fffff802`3e357113     ndis!ndisExpandDataPathStack<2,void __cdecl(void * __ptr64,_NET_BUFFER_LIST * __ptr64,unsigned long,unsigned long,unsigned long)>+0xae
0d ffff800b`52710340 fffff802`3e35977b     ndis!ndisInvokeNextReceiveHandler+0xdb
0e ffff800b`527103a0 fffff802`3e9712dc     ndis!NdisFIndicateReceiveNetBufferLists+0x350fb
0f ffff800b`52710450 fffff802`3e357019     wfplwfs!LwfLowerRecvNetBufferLists+0x14c
10 ffff800b`52710510 fffff802`3e356a87     ndis!ndisCallReceiveHandler+0xb9
11 ffff800b`52710560 fffff802`3e35d74a     ndis!ndisCallNextDatapathHandler<2,void * __ptr64 & __ptr64,void (__cdecl*& __ptr64)(void * __ptr64,_NET_BUFFER_LIST * __ptr64,unsigned long,unsigned long,unsigned long),void * __ptr64 & __ptr64,_NET_BUFFER_LIST * __ptr64 & __ptr64,unsigned long & __ptr64,unsigned long & __ptr64,unsigned long & __ptr64>+0x3f
12 ffff800b`527105b0 fffff802`3e357113     ndis!ndisExpandDataPathStack<2,void __cdecl(void * __ptr64,_NET_BUFFER_LIST * __ptr64,unsigned long,unsigned long,unsigned long)>+0xae
13 ffff800b`52710650 fffff802`3e333856     ndis!ndisInvokeNextReceiveHandler+0xdb
14 ffff800b`527106b0 fffff802`3b20c94d     ndis!NdisMIndicateReceiveNetBufferLists+0x116
15 ffff800b`52710740 fffff802`3b20bf9e     wdiwifi!CPort::IndicateFrames+0xad
16 ffff800b`52710880 fffff802`3b20b417     wdiwifi!CRxMgr::RxProcessAndIndicateNblChain+0x41e
17 ffff800b`527109b0 fffff802`3b20b268     wdiwifi!CRxMgr::RxInOrderDataInd+0x127
18 ffff800b`52710a60 fffff802`3b88d00d     wdiwifi!AdapterRxInorderDataInd+0x88
19 ffff800b`52710ab0 fffff802`3b88b3d9     rtwlanu!wdi_NotifyPeerData+0x3a5
1a ffff800b`52710b20 fffff802`3b92e1fd     rtwlanu!WDI_NotifyDataInQueue+0x9d
1b ffff800b`52710b80 fffff802`3bc3433e     rtwlanu!RxNotifyThreadCallback+0xcd
1c ffff800b`52710bc0 fffff802`38e79ca7     rtwlanu!Ndis6ThreadCallback+0x8e
1d ffff800b`52710bf0 fffff802`3901af64     nt!PspSystemThreadStartup+0x57
1e ffff800b`52710c40 00000000`00000000     nt!KiStartSystemThread+0x34
```
At this stage I could try to reverse engineer the `ndis!ndisCallNextDatapathHandler()` function and the rest of the call chain to figure out what `param2` is but I thought of trying if there's another way to do so. I thought of two things:

1. Look at each data type displayed in the Data Types Manager section in Ghidra.
2. In WinDBG, look at the register values since I had already broken into `Dot11Translate80211ToEthernetNdisPacket()` function and see I could figure out what data type they contain.

I had no luck with the second option (WinDBG) but I will revisit it soon. As for the first option, I was too lazy to go through each data type (probably over a couple of hundred at least) manually, so I asked ChatGPT to write a Ghidra script for me. Offcourse, it didn't work off the shelf. I had to understand it and rewrite it, but got it working.

So, this is what it found:

```
Find_Structs1.py> Running...
<omitted first 40 lines>
Structure '_IRP' contains 'MdlAddress' (_MDL *) at DECIMAL offset 8
Structure '_MDL' contains 'Next' (_MDL *) at DECIMAL offset 0
Structure '_NET_BUFFER_HEADER_s_0' contains 'CurrentMdl' (_MDL *) at DECIMAL offset 8
Structure '_NET_BUFFER_HEADER_s_0' contains 'MdlChain' (_MDL *) at DECIMAL offset 32
Structure '_NET_BUFFER_u_0_s_0' contains 'CurrentMdl' (_MDL *) at DECIMAL offset 8
Structure '_NET_BUFFER_u_0_s_0' contains 'MdlChain' (_MDL *) at DECIMAL offset 32
Structure 'DOT11_MDL_BOOKMARK' contains 'pNdisBuffer' (_MDL *) at DECIMAL offset 8
Structure 'DOT11_MDL_SUBCHAIN' contains 'pHead' (_MDL *) at DECIMAL offset 0
Structure 'DOT11_MDL_SUBCHAIN' contains 'pTail' (_MDL *) at DECIMAL offset 8
Structure 'DOT11_MDL_SUBCHAIN' contains 'pMdlBeforeTail' (_MDL *) at DECIMAL offset 16
Structure 'DOT11_MDL_SUBCHAIN' contains 'pOldTail' (_MDL *) at DECIMAL offset 24
Structure 'DOT11_RMH_UNDO_LOG' contains 'pNdisBuffer' (_MDL *) at DECIMAL offset 0
Structure 'DOT11_RMT_UNDO_LOG' contains 'pNewTail' (_MDL *) at DECIMAL offset 0
Structure 'DOT11_RMT_UNDO_LOG' contains 'pMdlAfterNewTail' (_MDL *) at DECIMAL offset 8
Structure 'NWIFI_MPDU' contains 'pHead' (_MDL *) at DECIMAL offset 0
Structure 'NWIFI_MPDU' contains 'pTail' (_MDL *) at DECIMAL offset 8
Structure 'NWIFI_MSDU' contains 'pHead' (_MDL *) at DECIMAL offset 40
Structure 'NWIFI_MSDU' contains 'pTail' (_MDL *) at DECIMAL offset 48
Find_Structs1.py> Finished!
```

I had to scroll through approximately 53 lines but it was much better than manually searching through the Data Types in Ghidra! The last to second line caught my attention, where it says the structure `NWIFI_MSDU` contains a pointer to `MDL` at offset 40. This offset is in decimal (not sure why Ghidra does it), but in in hexadecimal it's 0x28. If you recall, the `param2 + 0x28` is a pointer to `_MDL`. 

I think it's safe to assume that the second argument passed to the patched function `Dot11Translate80211ToEthernetNdisPacket()` is an MSDU structure. May be this is not the best way to figure out data type of the arguments passed to the patched function and it this approach (so, this Ghidra script) may not work in all scenarios. But I think, I now have something to continue my patch analysis further.



## References:
[1] https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmm aplockedpagesspecifycache
[2] https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/nblapi/nf-nbla pi-ndisadvancenetbufferlistdatastart
[3] https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/nbl/ns-nbl-net _buffer_list

