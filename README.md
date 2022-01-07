[comment]: # "Auto-generated SOAR connector documentation"
# ThreatCrowd

Publisher: Splunk  
Connector Version: 2\.0\.3  
Product Vendor: ThreatCrowd  
Product Name: ThreatCrowd  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app provides free investigative actions

### Supported Actions  
[test connectivity](#action-test-connectivity) - This action will run the test domain to check the connectivity with the threat crowd server and this action will not affect any other actions irrespective of the connectivity result  
[lookup domain](#action-lookup-domain) - Queries ThreatCrowd for domain info  
[lookup email](#action-lookup-email) - Queries ThreatCrowd for email info  
[lookup ip](#action-lookup-ip) - Queries ThreatCrowd for IP info  
[file reputation](#action-file-reputation) - Queries ThreatCrowd for file reputation  

## action: 'test connectivity'
This action will run the test domain to check the connectivity with the threat crowd server and this action will not affect any other actions irrespective of the connectivity result

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup domain'
Queries ThreatCrowd for domain info

Type: **investigate**  
Read only: **True**

Here the limit parameter will limit the response for the following keys\: 'hashes', 'subdomains', 'resolutions'

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain` 
**response\_limit** |  optional  | Response length limit \(0 = all, default 10\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.parameter\.response\_limit | numeric | 
action\_result\.data\.\*\.emails | string |  `email` 
action\_result\.data\.\*\.permalink | string |  `url` 
action\_result\.data\.\*\.resolutions\.\*\.ip\_address | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.hashes | string |  `hash`  `md5` 
action\_result\.data\.\*\.resolutions\.\*\.last\_resolved | string | 
action\_result\.data\.\*\.response\_code | string | 
action\_result\.data\.\*\.subdomains | string |  `domain` 
action\_result\.data\.\*\.votes | numeric | 
action\_result\.summary\.Message | string | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup email'
Queries ThreatCrowd for email info

Type: **investigate**  
Read only: **True**

Here the limit parameter will limit the response for the following key\: 'domains'

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email to query | string |  `email` 
**response\_limit** |  optional  | Response length limit \(0 = all, default 10\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.response\_limit | numeric | 
action\_result\.data\.\*\.domains\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.permalink | string |  `url` 
action\_result\.data\.\*\.response\_code | string | 
action\_result\.summary | string | 
action\_result\.summary\.Message | string | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup ip'
Queries ThreatCrowd for IP info

Type: **investigate**  
Read only: **True**

Here the limit parameter will limit the response for the following keys\: 'hashes', 'resolutions'

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip`  `ipv6` 
**response\_limit** |  optional  | Response length limit \(0 = all, default 10\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.parameter\.response\_limit | numeric | 
action\_result\.data\.\*\.hashes | string |  `hash`  `md5` 
action\_result\.data\.\*\.permalink | string |  `url` 
action\_result\.data\.\*\.resolutions\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.resolutions\.\*\.last\_resolved | string | 
action\_result\.data\.\*\.response\_code | string | 
action\_result\.data\.\*\.votes | numeric | 
action\_result\.summary | string | 
action\_result\.summary\.Message | string | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'file reputation'
Queries ThreatCrowd for file reputation

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of the file in question | string |  `hash`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `md5` 
action\_result\.data\.\*\.domains | string |  `domain` 
action\_result\.data\.\*\.ips | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.permalink | string |  `url` 
action\_result\.data\.\*\.response\_code | string | 
action\_result\.data\.\*\.scans | string | 
action\_result\.data\.\*\.sha1 | string |  `hash`  `sha1` 
action\_result\.summary\.Message | string | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 