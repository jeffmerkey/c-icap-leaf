<a name="br1"></a> 

**C-ICAP-Leaf**

**Overview**

**Document v1.3**

**Prepared by Jeﬀ Merkey**



<a name="br2"></a> 

**What is Leaf?**

Leaf is a high performance intercept and storage technology which allows all

web pages accessed through either a standard proxy server or a transparent

proxy server to be stored at high data rates to back end databases. Leaf

decrypts and decompresses all HTTP and HTTPS traﬃc, analyzes the traﬃc,

then stores it into a background database with a full text search capability.

The database supports a Google-like search engine interface for searching

and reviewing captured pages to ensure corporate policy compliance,

allowing system administrators to check for inappropriate usage of their

networks, and quickly detects pages from adult themed websites, social

networking websites, job search websites, and forum websites such as

Wikipedia.



<a name="br3"></a> 

Leaf solves the customer problem of enabling full visibility of web site traﬃc

on corporate networks for system administrators and also supports rapid

searching of captured web content for verifying that corporate networks are

being used in compliance with corporate network use policies.

The interface used to achieve this is the same interface commonly used by

proxy servers for url ﬁltering and ant-virus web page scanning, and is

implemented based on the ICAP standard (Internet Content Adaptaton

Protocol) and associated communicaton protocols. Virtually all commercial

proxy servers, including SQUID and the Microsof Proxy Server, fully support

the ICAP protocol.

The ICAP architecture is typically implemented as a standalone server which

receives ICAP messages from the host proxy server, allowing web pages to



<a name="br4"></a> 

be scanned for sofware viruses and sending ICAP response messages and

virus-free HTML content to proxy users. Leaf takes this a step further and

decompresses received compressed web content, analyzes the content, then

stores it into an SQL based data storage model.

The Leaf ICAP intercept module is proprietary and ‘C’ language based and is

provided to the customer as a binary module and each module requires a

license which is ted to the detected hardware on each customer system to

prevent piracy and unauthorized copying. The Leaf binary modules are not

open sourced. The base C-ICAP server is licensed under the LGPL (lesser

GPL) which means that proprietary binary modules are fully supported and

allowed to run tme link against the C-ICAP server core without the

requirement they be open sourced.



<a name="br5"></a> 

The Leaf search engine console for searching captured web pages is PHP

based and the source code for the Web Console is included with Leaf, which

provides customers the ability to modify and customize the search engine

for each customer’s unique requirements. This customer ﬂexibility is

further enhanced by allowing Leaf to run with either Linux or Windows

based proxy servers and a range of SQL server architectures via ODBC

modules.

The base technology is currently implemented on Linux (Centos 7). The base

technology comprises four distnct technologies which can be installed on a

single appliance, or they can be distributed across several servers which can



<a name="br6"></a> 

be a mixture of Linux and Windows systems. At present, the C-ICAP server

and modules is the only component which requires a Linux based server.

Because Proxy Server protocols, ICAP protocols, SQL protocols, and PHP web

services are all fully distributed models, these four components can be

distributed across multple systems based on network topology and easily

clustered, allowing multple Leaf ICAP appliances or servers to communicate

to a backend SQL database cluster or storage array by using commodity

platorm services.

This ﬂexibility allows Leaf to be installed on most cloud based systems such

as Azure and AWS as either a standalone ICAP intercepton server, or a

combined appliance image with SQUID and C-ICAP atached to a back end

database server. The PHP search engine console can also be installed on a

standalone system with remote SQL access or it can be combined with the

other three components on a single appliance. Providing the customer with

the PHP source code is an atractve opton and allows customers the

freedom to modify the search engine to provide speciﬁc reports and data

views based on each customers partcular requirements. Providing the PHP

source code for the search console also creates opportunites for consultng

services and custom console development for customers who are willing to

pay for such services rather than do the development work in-house, since

the customer essentally owns their own unique version and enhancements

of the search engine.

The ability of Leaf to make use of commodity SQL database platorms is an

atractve approach for most customers who probably already have a

preexistng database infrastructure for their corporate data. This approach

means that minimal integraton overhead is required to implement Leaf in

existng infrastructures and cloud based systems. If customers are already

using SQUID or another proxy server, Leaf can be integrated as a standalone

ICAP server or into any preexistng C-ICAP based installaton.



<a name="br7"></a> 

Modern network appliances have evolved to the point they provide

suﬃcient disk and network bandwidth to support SQL based stream to disk

capability. Testng has demonstrated that even a modest desktop system

can meet the minimum performance requirements for HTML stream to disk

for a small to medium sized oﬃce conﬁguraton.

Deep Packet Capture vs. Proxy Intercepton

During the late 1990’s and early 2000’s, networking solutons available to

customers for achieving network visibility of website traﬃc were for the

most part reliant on deep packet capture technologies which captured all

network traﬃc by streaming captured network packets to disk, then

employed some form of reconstructon console to reassemble and display

web pages, fp, P2P, and other forms of network traﬃc. Over tme, the

internet began to evolve towards wholesale adopton of TLS and HTTPS

protocols, with virtually all web based traﬃc being encrypted and utlizing

compression techniques as of 2020.

Because of the way that public/private key encrypton models functon, most

deep packet capture technologies became unable to eﬃciently process or

decrypt HTTPS traﬃc without access to the secret key for a partcular server.

Although deep packet capture technologies do enable a complete view of

who is on your network and what nodes they are communicatng with, these

technologies do not enable the ability to view the actual content being sent

over the network. SSL/TLS Proxy intercepton (also called SSL Bumping)

began to appear in network proxy servers such as SQUID in order to enable

web pages to be decrypted to detect viruses and certain types of prohibited

urls or web content.

Modern proxy servers all support SSL bumping in some form for proxy

clients, and both standard proxy and transparent proxy modes are fully

supported currently by SQUID 4.10.



<a name="br8"></a> 

What is SSL Bumping?

SSL bumping is service provided by a proxy server which decrypts and

encrypts HTTP transactons between the proxy client and the remote web

server, allowing HTML content to be decrypted and reviewed. Internet

Web Servers which are conﬁgured to support HTTPS connectons are

conﬁgured with an SSL certﬁcate which is used to establish a secure

connecton between the server and clients. When a proxy client accesses a

remote server via the proxy server, it normally uses the remote servers SSL

certﬁcate to establish a secure connecton to it.



<a name="br9"></a> 

With SSL Bumping enabled, a second SSL certﬁcate is hosted on the proxy

server which is used to establish an SSL connecton between the proxy

server and the proxy client, and the proxy server then establishes an

independent SSL connecton to the remote web server with the remote

servers SSL certﬁcate. This creates two distnct and independent SSL

connectons, one between the proxy client and the proxy server, and

another between the proxy server and the remote web server. Data ﬂows

between the remote web server and the proxy server are then decrypted

and passed to an ICAP server for analysis before being re-encrypted and sent

to the proxy client. ICAP analysis services can include virus detecton, url

blocking, language translaton, or intercepton of the web pages for capture.

From the proxy clients perspectve, the certﬁcate presented to it appears to

belong to the remote server. This is because the proxy server essentally

“forges” the remote web servers identty into the SSL certﬁcate hosted on

the proxy server before sending it to the proxy client. SSL Bumping works

well for almost all modern websites, and in almost all situatons cannot be

detected by either the web browser or proxy client applicatons. Most

customers who use ClamAV ant-virus detecton with SQUID already have

their own internal SSL certﬁcates installed they use for this purpose, and

may be already using SSL Bumping to support ant-virus sofware.

HTTP Compression Support

When a web browser sends an HTTP request to a remote web server,

modern web browsers atach a message header to the HTTP request

specifying which compression/decompression models are supported by the

web browser. Most web traﬃc is both encrypted and compressed by the

web server in order to improve performance and decrease bandwidth usage.

By way of example, Google News main pages are over 3MB in size and are

compressed to a size of 400K before being transmited over the internet.

Leaf supports all current compression/decompression models used by web

servers on the internet. The current supported compression/decompression



<a name="br10"></a> 

models currently in use on the internet are deﬂate/inﬂate, gzip/gunzip,

bzip/bunzip, bzip2/bunzip2, and brotli (Google).

Implementaton

The current Leaf server appliance was developed on Red Hat Enterprise

Server version 7/CentOS 7. The appliance uses a Centos 7 base operatng

system with the additonal Leaf Server RPMs (Red Hat Packages/Modules).

The PHP web console can run on any web server that supports PHP,

including Linux and Windows Web servers. The C-ICAP server and Leaf ICAP

Intercept modules currently run on Centos7, however the C-ICAP server can

be recompiled to run on Windows.

C-ICAP can also be conﬁgured to run on a diﬀerent appliance from the Proxy

server in order to increase available port sockets for large numbers of web

clients. In deployments which host large numbers of web proxy clients per

proxy server, it is strongly recommended to deploy the proxy server on a

separate appliance chassis from the C-ICAP server, and that both be

conﬁgured to use as a minimum a gigabit network backbone between the

proxy server and the C-ICAP server, since this will double the available port

sockets for client and server usage.

In conﬁguratons which support a small number of proxy clients, the proxy

server and ICAP server can be combined along with MySQL and the Leaf

Console web server on a single appliance chassis.

The Leaf Intercept module is released under the Lesser GPL. The Lesser GPL

allows proprietary closed source modules such as the Leaf intercept module

to link to it. The Leaf appliance build listng consists of the following binary

RPM modules/Images which can be installed with the rpm package manager

utlity (rpm or yum). Using a Yum repository allows end users to download

and install updated modules or new features as required in an automated

manner:



<a name="br11"></a> 

**GPL v2**

CentOS 7 DVD Image (x86\_64 build 1908)

squid4-4.10-1.el7.leaf.x86\_64.rpm (Squid 4.10 Core)\*

squid4-debuginfo-4.10-1.el7.leaf.x86\_64.rpm

*\*Note: There are no changes to the Squid base source code required to support Leaf. The only changes*

*are to the rpm build ﬁle (squid4.spec) to enable compile tme build optons to enable icap client*

*support and SSL Bumping to decrypt web sessions.*

**Lesser GPL v2.1**

c-icap-0.5.6-1.el7.leaf.x86\_64.rpm (C-ICAP Core)\*

c-icap-debuginfo-0.5.6-1.el7.leaf.x86\_64.rpm

c-icap-devel-0.5.6-1.el7.leaf.x86\_64.rpm

c-icap-ldap-0.5.6-1.el7.leaf.x86\_64.rpm

c-icap-libs-0.5.6-1.el7.leaf.x86\_64.rpm

c-icap-perl-0.5.6-1.el7.leaf.x86\_64.rpm

c-icap-progs-0.5.6-1.el7.leaf.x86\_64.rpm

*\*Note: There are two bug ﬁxes to the base ICAP code and an additonal posix shared memory*

*segment allocated. These ﬁxes were to correct two separate memory leaks detected during*

*load testng and also enable shared memory support for ICAP server statstcs for the Leaf*

*Server Monitor.*

c-icap-leaf-0.5.6-1.el7.leaf.x86\_64.rpm (Leaf Intercept Module)

leafcon-1.3-el7.leaf.el7.noarch.rpm (Leaf PHP Web Console)

leafmon-1.3-el7.leaf.el7.x86\_64.rpm (Leaf Server Monitor)



<a name="br12"></a> 

Leaf Search Console

The Leaf search console is a PHP based standalone web server which can

access, scan, and reconstruct web pages for viewing by a network

administrator afer they have been captured and writen into an SQL

database by the Leaf intercept module. The web console interface is

PHP/MySQL based and will functon with any HTTP web browser. The PHP

base code can be easily modiﬁed or enhanced based on customer

requirements.

Leaf Web Console top of page search panel. The search interface is google-like and can be conﬁgured

to use a variety of diﬀerent style sheets to change the look and feel of the web console.



<a name="br13"></a> 

The Leaf web server can scan, load, and then run captured pages “live” on

the internet from the server cache as well as providing a statc view of a

cached web page. The console also will display the raw HTML page text

(HTML), fulltext search extracts (condensed), IP Address informaton for

monitored proxy clients, DNS names, proxy user accounts, embedded page

objects such as PDF ﬁles, as well as a list of all links and images referenced

by a partcular page, along with HTTP request and response headers for a

partcular page.

Leaf Console botom of page search panel. The botom search panel provides paginaton

support similar to a google-like search panel

The web console provides a google-like search engine interface for searching

captured pages and provides fulltext search capability of captured web



<a name="br14"></a> 

content. Captured pages older than 30 days can be conﬁgured to be

automatcally archived into another database, or they can be output as .sql

ﬁles or CSV ﬁles (comma delimited ﬁles), which will increase database search

speeds of the most recent data. If multple Leaf capture appliances are

deployed together, each appliance can be conﬁgured to use a unique

database table name or database server name.

Leaf Console reconstructed web page for “Emerald” using the “live” view. This view loads the web

page, performs href, img, and relatve url ﬁxup to point to the originatng site, then runs the page

scripts as live.

These back-end databases can then be conﬁgured to record web pages in

parallel SQL tables to boost performance, or they can also be conﬁgured to

funnel into a single high availability database or database cluster. The



<a name="br15"></a> 

console can also be enabled to provide combined views of captured data

across multple tables or databases.

Leaf Console reconstructed web page from a captured Gmail session “cached” view.

This view loads the web page from statc storage. This viewing mode is useful for sites that require a

login such as gmail. The cached page can be viewed independent of the live server in this mode.

The Web console also supports page tagging, and individual pages can be

tagged which will allow them to be collected and displayed in a condensed

console view. This allows network administrators to tag pages which may be

of interest for later review. By default, the Leaf database module only stores

pages of the text/html MIME type. Leaf can be conﬁgured to record all non

text/html pages as well, although doing so can utlize considerable database

storage and negatvely impact end user web browser performance when



<a name="br16"></a> 

going through a proxy server since all of this content has to be sent in total

to the ICAP server instead of only text/html pages.

Since the majority of non text/html pages contain mostly javascripts, json

objects, or video content, these ﬁles are not required in order to run a

captured page as live. When the Web console runs a captured page as

“live” from it ’s page cache, the PHP code analyzes all url link ﬁelds, images,

and scripts and performs a url ﬁxup which allows cached pages to be fully

reconstructed in the Web Console web browser. The web console also

provides the original url which can simply be clicked on to visit the website

the page originated from with the same functonality as google’s web

interface.

ICAP servers by default are conﬁgured to receive 1024 bytes of preview data

for each web object sent from a proxy server for review by ICAP services and

modules. Before ICAP signals the proxy server to send the entre object to

the ICAP server, ICAP modules have the opton of signaling the proxy server

with a 204 return code which informs the proxy server to release the end

user web client request and send the web data to the proxy client without

ICAP module review or receipt. For text/html pages, by default Leaf tells

the proxy server to send the entre page to the ICAP server for processing

and returns a 204 Status for any page preview which is not text/html

content, which dramatcally improves ICAP server performance.

The Web console will also display a date ordered digest view of daily web

traﬃc which can be organized and searched by IP address, proxy username,

DNS hostnames, and for mult-appliance conﬁguratons, a local view of each

unique capture appliance web pages. ICAP provides LDAP library bindings

and LDAP support can be easily integrated into the Leaf Intercept server and

Leaf Web Console for resolving user names from IP addresses or DNS names.

The Leaf Intercept module also stores SQUID Proxy username and login

informaton from the proxy server allowing proxy clients to be tracked.



<a name="br17"></a> 

Leaf Server Monitor

The Leaf Server Monitor (leafmon) is a Unix terminal based monitoring

program that allows system administrators to monitor internal operatng

server statstcs (such as disk I/O stats, processor stats, memory stats,

networking stats), C-ICAP server statstcs, SQL database usage and storage

statstcs, and Leaf Intercept Module Statstcs.

Leaf Server monitor main menu (leafmon). The utlity displays total disk and network throughput,

processor utlizaton, memory usage, Leaf Intercept Server statstcs, C-ICAP Server statstcs, and

MySQL statstcs.

The Leaf monitoring program is writen under Linux ncurses. Because the

program is ncurses based, it will run across all ncurses supported terminals



<a name="br18"></a> 

and terminal type emulatons. This allows remote administrators to invoke

the Leaf monitor via a BASH shell or secure shell (ssh) session as well as from

hardware based vt100 terminal types and above.

Leaf Server monitor server summary for the Leaf Intercept module. This session reports that the Leaf

Server is writng 1,208 html pages per second into the MySQL database with 1,247 peak html pages

per second. The Leaf Server also reports it has writen a total of 385,484 html pages to the MySQL

database.

The Leaf monitor allows visibility into system performance and provides Leaf

Intercept module statstcs such as pages per second, total pages stored, SQL

database storage usage, Leaf conﬁguraton and operaton data, and detailed

ICAP server statstcs. It also displays disk utlizaton and disk reads and

writes per second and network sends and receives per second.



<a name="br19"></a> 

The Leaf monitor is extremely useful for providing visibility of performance

and resource usage of a real tme ICAP Server with actve Leaf html

intercepton in test environments and customer deployments. The leafmon

tool enables rapid resoluton of performance issues, tuning, or conﬁguraton

issues.

Leaf Server Monitor detailed disk statstcs panel. This panel lists all atached local and remote hard

disk storage and live I/O statstcs along with disk utlizaton. It also reports merged read and write

requests and pending I/O.

The Leaf Server Monitor also provides detailed statstcs for the C-ICAP

server including number of actve servers, actve processes, threads per

process, total pages processed, total pages which were skipped with a 204

response (released and not processed by ICAP server), actve C-ICAP



<a name="br20"></a> 

modules, and C-ICAP module statstcs. REQMODS and RESPMODS are also

tracked (proxy HTTP requests and remote web server HTTP responses).

Administrators can view live ICAP sessions and session data in order to

monitor C-ICAP performance, throughput, and network utlizaton.

Leaf Server Monitor C-ICAP summary panel. This panel displays real-tme performance and

transactonal statstcs for the main server core as well as for C-ICAP binary modules.

It is important to note that C-ICAP receives and processes both HTTP

requests sent to a remote web server by the proxy server (REQMODS) and

responses received from the remote server through the proxy server

(RESPMODS). “ALLOW 204” is the number of pages the ICAP server told the

proxy server it was skipping a proxy request (page was not text/html MIME

type).



<a name="br21"></a> 

Leaf Server Monitor C-ICAP summary for the Leaf and Leaﬁnfo C-ICAP binary modules. The monitor

reports requests, responses, 204 status (skipped), along with bytes in and out for HTTP headers and

HTML body data.

The Leaf Server Monitor provides ﬁve server-wide summary panels which

report real-tme statstcs:

1\. System Summary

2\. Network Summary

3\. Disk Summary

4\. C-ICAP Summary

5\. MYSQL Summary



<a name="br22"></a> 

1\. System Summary – provides detailed system level statstcs such as server

up tme, system load averages, processor utlizaton, memory usage, process

states, total disk read/writes, network send/receives, Leaf Intercept

summary statstcs, MYSQL summary statstcs and conﬁguraton.

Leaf Server Monitor System Summary (expanded view)



<a name="br23"></a> 

2\. Network Summary – provides detailed network adapter statstcs, total

send/receives, hardware adapter statstcs, and a listng of all actve and

detected network adapters.

Leaf Server Monitor Network Summary (expanded view)



<a name="br24"></a> 

3\. Disk Summary – provides detailed view of local and remote disk storage,

disk utlizaton, disk read/writes per second, pending I/O requests, elevator

and coalesced disk I/O requests (read and write merges), and I/O proﬁling of

all disk devices as well as partton based views of I/O operatons and data

rates per actve disk parttons.

Leaf Server Monitor Disk Summary (expanded view)



<a name="br25"></a> 

4\. ICAP Summary – provides detailed view of all C-ICAP server transactons,

including ICAP requests per second, live ICAP server processes, HTTP bytes

both in and out, detailed breakdown of loaded C-ICAP module statstcs,

errors, skipped requests (allow 204 responses), and total HTTP header and

BODY data statstcs.

Leaf Server Monitor C-ICAP Summary (expanded view)



<a name="br26"></a> 

5\. MYSQL Summary – provides detailed Leaf Intercept module statstcs

including pages processed per second, peak statstcs, average data rates,

dropped pages, page write errors, module conﬁguraton optons, MySQL

conﬁguraton optons, current free space available to the MySQL database,

and MySQL conﬁguraton optons such as target database name and target

table name for a partcular Leaf module or appliance image.

Leaf Server Monitor MYSQL Summary (expanded view)

