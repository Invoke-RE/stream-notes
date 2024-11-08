## Donex Ransomware

* Uses https://github.com/Mbed-TLS/mbedtls
* Uses Salsa20
* Configuration is decrypted using a single-byte XOR loop with 0xa9 and results in the configuration:
```
<?xml version='1.0' encoding='UTF-8'?>
<root>
	<white_extens>386;adv;ani;bat;bin;cab;cmd;com;cpl;cur;deskthemepack;diagcab;diagcfg;diagpkg;dll;drv;exe;hlp;icl;icns;ico;ics;idx;lnk;mod;mpa;msc;msp;msstyles;msu;nls;nomedia;ocx;prf;ps1;rom;rtp;scr;shs;spl;sys;theme;themepack;wpx;lock;key;hta;msi;pdb;search-ms</white_extens>
	<white_files>bootmgr;autorun.inf;boot.ini;bootfont.bin;bootsect.bak;desktop.ini;iconcache.db;ntldr;ntuser.dat;ntuser.dat.log;ntuser.ini;thumbs.db;GDIPFONTCACHEV1.DAT;d3d9caps.dat</white_files>
	<white_folders>$recycle.bin;config.msi;$windows.~bt;$windows.~ws;windows;boot;program files;program files (x86);programdata;system volume information;tor browser;windows.old;intel;msocache;perflogs;x64dbg;public;all users;default;microsoft;appdata</white_folders>	
	<kill_keep>sql;oracle;mysq;chrome;veeam;firefox;excel;msaccess;onenote;outlook;powerpnt;winword;wuauclt</kill_keep>
	<services>vss;sql;svc$;memtas;mepocs;msexchange;sophos;veeam;backup;GxVss;GxBlr;GxFWD;GxCVD;GxCIMgr</services>
	<black_db>ldf;mdf</black_db>
	<encryption_thread>30</encryption_thread>
	<walk_thread>15</walk_thread>
	<local_disks>true</local_disks>
	<network_shares>true</network_shares>
	<kill_processes>true</kill_processes>
	<kill_services>true</kill_services>
	<shutdown_system>true</shutdown_system>
	<delete_eventlogs>true</delete_eventlogs>	
	<cmd>wmic shadowcopy delete /nointeractive</cmd>
	<cmd>vssadmin Delete Shadows /All /Quiet</cmd>
	<content>            !!! DoNex ransomware warning !!!

&gt;&gt;&gt;&gt; Your data are stolen and encrypted

	The data will be published on TOR website if you do not pay the ransom 

	Links for Tor Browser:
	http://g3h3klsev3eiofxhykmtenmdpi67wzmaixredk5pjuttbx7okcfkftqd.onion
	

&gt;&gt;&gt;&gt; What guarantees that we will not deceive you? 

	We are not a politically motivated group and we do not need anything other than your money. 
    
	If you pay, we will provide you the programs for decryption and we will delete your data. 
    
	If we do not give you decrypters, or we do not delete your data after payment, then nobody will pay us in the future. 
	
	Therefore to us our reputation is very important. We attack the companies worldwide and there is no dissatisfied victim after payment.
    

&gt;&gt;&gt;&gt; You need contact us and decrypt one file for free on these TOR sites with your personal DECRYPTION ID

	Download and install TOR Browser https://www.torproject.org/
	Write to a chat and wait for the answer, we will always answer you. 
	
	You can install qtox to contanct us online https://tox.chat/download.html
	Tox ID Contact: 2793D009872AF80ED9B1A461F7B9BD6209744047DC1707A42CB622053716AD4BA624193606C9
	
	Mail (OnionMail) Support: donexsupport@onionmail.org
	
&gt;&gt;&gt;&gt; Warning! Do not DELETE or MODIFY any files, it can lead to recovery problems!

&gt;&gt;&gt;&gt; Warning! If you do not pay the ransom we will attack your company repeatedly again!
	</content>
	<ico>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</ico>
</root>
```

#### Sidekick Generated Cryptography Script
```
# Define the LLMOperator for detecting cryptography-related calls
crypto_detector = LLMOperator("Identify cryptography-related calls in this function.")

# Open an index to store the results
with open_index(bv, "Cryptography Related Calls") as index:
    # Iterate over all defined functions in the binary
    for i, func in enumerate(iter_defined_functions(bv)):
        # Notify progress
        notify_progress(i, len(bv.functions), "Analyzing functions for cryptography-related calls")
        
        # Use the LLMOperator to analyze the function
        result = crypto_detector(func)
        
        # If cryptography-related calls are found, add them to the index
        if result.get("cryptography_related_calls"):
            index.add_entry(func, {"Cryptography Related Calls": result["cryptography_related_calls"]})
```

#### Plaintext File Recovery PowerShell

* [find_pt_files.ps1](find_pt_files.ps1)

#### Ransomware Decryptor

* [recover_stream.py](recover_stream.py)

#### References

* [https://dissect.ing/posts/donex/](https://dissect.ing/posts/donex/)
* [https://www.crysearch.nl/files/research/recon2024_donex.pdf](https://www.crysearch.nl/files/research/recon2024_donex.pdf)
