

#include "../../common.h"
#include "c_icap/c-icap.h"
#include "c_icap/service.h"
#include "c_icap/header.h"
#include "c_icap/body.h"
#include "c_icap/simple_api.h"
#include "c_icap/debug.h"
#include <assert.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/mman.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netipx/ipx.h>
#include <neteconet/ec.h>
#include <linux/if_slip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if_arp.h>
#include <neteconet/ec.h>
#include <linux/atalk.h>
#include <linux/netdevice.h>
#include <asm/types.h>
#include <asm/param.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <time.h>
#include <ncurses.h>
#include <linux/hdreg.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <sys/utsname.h>

#include <linux/ethtool.h> 
#include <linux/sockios.h>

#include <ctype.h>
#include "srv_leaf.h"
#include "srv_stats.h"

static LICENSE_KEY seed;
static LICENSE_KEY license;
static const char *seedkey = "leaflinux398gu574yj923jk7d03";
static int seedlen;
static const char *licensekey = "Hyt93wjr324hdgso34roe5vjgh31";
static int licenselen;
static int key_index;
static struct _key_array {
	int key_len[MAX_ADAPTERS];
	unsigned char key_array[MAX_ADAPTERS][128];
} keys;

static int xor_encrypt(unsigned char *data, int datalen, unsigned char *key, int keylen)
{
	register int i;
	
	if (!keylen)
		return 0;

	for (i = 0; i < datalen && keylen; i++) 
		data[i] = data[i] ^ key[i % keylen];
	return i;
}

static unsigned char *get_random_bytes(unsigned char *data, int datalen)
{
	register int i;

	srand(time(0));
	for (i=0; i < datalen; i++) 
		data[i] = (unsigned char)random();
	return data;
}

size_t read_hex_file(FILE *inf, unsigned char *dest)
{
	size_t count = 0;
	int n;
	if (dest == NULL) {
		unsigned char c;
		while ((n = fscanf(inf, "%hhx", &c)) == 1 ) {
			count++;
		}
	}
	else {
		while ((n = fscanf(inf, "%hhx", dest)) == 1 ) {
			dest++;
		}
	}
	if (n != EOF) {
		;  // handle syntax error
	}
	return count;
}

void load_hex_file(void)
{
	FILE *inf = fopen("hex.txt", "rt");
	size_t n = read_hex_file(inf, NULL);
	rewind(inf);
	unsigned char *hex = malloc(n);
	read_hex_file(inf, hex);
	fclose(inf);
	free(hex);
}

static char *get_name(char *name, char *p)
{
	while (isspace(*p))
		p++;
	while (*p) {
		if (isspace(*p))
			break;
		if (*p == ':')
		{
			// could be an alias
			char *dot = p, *dotname = name;

			*name++ = *p++;

			while (isdigit(*p))
				*name++ = *p++;

			if (*p != ':')
			{
				// it wasn't, backup
				p = dot;
				name = dotname;
			}

			if (*p == '\0')
				return NULL;

			p++;
			break;
		}
		*name++ = *p++;
	}
	*name++ = '\0';
	return p;
}

static int if_get(int skfd, char *ifname)
{
	struct ifreq ifr;
	struct ethtool_cmd cmd;
	struct ethtool_drvinfo drvinfo;
	unsigned char *hwaddr;
	struct sockaddr hwa;

	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0) 
		return 0;

	memset(&ifr, 0, sizeof ifr);
	memset(&cmd, 0, sizeof cmd);
	memset(&drvinfo, 0, sizeof drvinfo);
	strcpy(ifr.ifr_name, ifname);

	ifr.ifr_data = &drvinfo;
	drvinfo.cmd = ETHTOOL_GDRVINFO;

	if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
		close(sock);
		return 0;
	}
	close(sock);

	memset(&ifr, 0, sizeof ifr);
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0)
	{
		hwa = ifr.ifr_hwaddr;
		hwaddr = (unsigned char *)hwa.sa_data;
	}	
	else
	{
		memset(&hwa, 0, sizeof(struct sockaddr));
		hwaddr = (unsigned char *)hwa.sa_data;
	}
	if (hwaddr && drvinfo.bus_info)
	{
		unsigned char key[1024]; 
		int keylen;

		// skip taps, tunnels, bridges, and unknown device types
		if (!strncasecmp("n/a", drvinfo.bus_info, 3) || !strncasecmp("tap", drvinfo.bus_info, 3) ||
			!strncasecmp("tun", drvinfo.bus_info, 3) || !strncasecmp("bridge", drvinfo.bus_info, 6))
			return 0;

		// skip USB network adapters
		if (strcasestr(drvinfo.bus_info, "usb"))
			return 0;

		if (!strncasecmp("en", ifname, 2) || !strncasecmp("wl", ifname, 2) || !strncasecmp("ww", ifname, 2)) {
			keylen = snprintf((char *)key, 1024, "%s/%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x/%s",
				ifname, hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3],
				hwaddr[4], hwaddr[5], (unsigned char *)drvinfo.bus_info);
			if (keylen > 128) 
				keylen = 128;

			keys.key_len[key_index] = keylen;
			memmove(&keys.key_array[key_index][0], key, keylen);
			key_index++;			
    			//ci_debug_printf(4, "leaf: detect -> key: %s keylen: %i pid: %ld\n", key, keylen, (unsigned long)getpid());
			return keylen;	
		}

	}	
	return 0;
}

int get_network_keys(void)
{
	FILE *fp;
	char buf[1024];
	int skfd;

	key_index = 0;
	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0)
		return skfd;

	fp = fopen("/proc/net/dev", "r");
	if (!fp)
	{
		close(skfd);
		return -1;
	}
	if (!fgets(buf, sizeof buf, fp)) // eat line
	{
		fclose(fp);
		close(skfd);
		return 0;
	}
	if (!fgets(buf, sizeof buf, fp))
	{
		fclose(fp);
		close(skfd);
		return 0;
	}
	while (fgets(buf, sizeof buf, fp))
	{
		char name[IFNAMSIZ];
		if (key_index >= (MAX_ADAPTERS - 1))
			break;
		get_name(name, buf);
		if_get(skfd, name);
	}
	fclose(fp);
	close(skfd);

	int i, keylen = 0;
	unsigned char *key = NULL;

	for (i=0; i < key_index; i++) {
		//ci_debug_printf(4, "leaf: search -> key: %s keylen: %i\n", &keys.key_array[i][0], keys.key_len[i]);
		if (!strncasecmp((const char *)&keys.key_array[i][0], "en", 2) ||
			!strncasecmp((const char *)&keys.key_array[i][0], "wl", 2) ||
			!strncasecmp((const char *)&keys.key_array[i][0], "ww", 2)) {
			keylen = keys.key_len[i];
			key = &keys.key_array[i][0];
			//ci_debug_printf(4, "leaf: select -> key: %s keylen: %i\n", key, keylen);

			if (!keylen) {
				//ci_debug_printf(4, "leaf: keylen was %i\n", keylen);
				continue;
			}
			if (keylen > 128) 
				keylen = 128;
			//ci_debug_printf(4, "leaf: key: %s keylen: %i\n", key, keylen);

			seedlen = strlen(seedkey);	
			//ci_debug_printf(4, "leaf: seedkey: %s seedlen: %i\n", seedkey, seedlen);
			licenselen = strlen(licensekey);	
			//ci_debug_printf(4, "leaf: licensekey: %s licenselen: %i\n", licensekey, licenselen);
		
		        get_random_bytes(seed.buffer, LSIZE);
		        seed.s.signature = SEED_SIGNATURE;
			seed.s.keylen = keylen;
			memmove(&seed.s.key, key, keylen);
			xor_encrypt(seed.s.key, seed.s.keylen, (unsigned char *)licensekey, licenselen);
			xor_encrypt(seed.buffer, LSIZE, (unsigned char *)seedkey, seedlen);

			fp = fopen("/etc/c-icap/leaf.seed", "wb");
			if (fp) {
				int writelen = fwrite(seed.buffer, 1, LSIZE, fp);
				if (writelen == LSIZE)
					ci_debug_printf(4, "leaf: seed data written to \"/etc/c-icap/leaf.seed\"\n");
				fclose(fp);
			}

#ifdef AUTO_GENERATE_LICENSE
			xor_encrypt(seed.buffer, LSIZE, (unsigned char *)seedkey, seedlen);
		        seed.s.signature = LICENSE_SIGNATURE;
			xor_encrypt(seed.buffer, LSIZE, (unsigned char *)key, keylen);
			fp = fopen("/etc/c-icap/leaf.license", "wb");
			if (fp) {
				int writelen = fwrite(seed.buffer, 1, LSIZE, fp);
				if (writelen == LSIZE)
					ci_debug_printf(4, "leaf: license data written to \"/etc/c-icap/leaf.license\"\n");
				fclose(fp);
			}
#endif
			break;
		} 
	}
	return 0;
}

LICENSE_KEY *get_license(void)
{
	FILE *fp;
	int i, keylen = 0;
	unsigned char *key = NULL;

	fp = fopen("/etc/c-icap/leaf.license", "rb");
	if (fp) {
		int readlen = fread(license.buffer, 1, LSIZE, fp);
		if (readlen == LSIZE) {
			ci_debug_printf(4, "leaf: license data read from \"/etc/c-icap/leaf.license\"\n");
			for (i=0; i < key_index; i++) {
				//ci_debug_printf(4, "leaf: search -> key: %s keylen: %i\n", &keys.key_array[i][0], keys.key_len[i]);
				keylen = keys.key_len[i];
				key = &keys.key_array[i][0];
				if (!keylen) {
					//ci_debug_printf(4, "leaf: keylen was %i\n", keylen);
					continue;
				}
				if (keylen > 128) 
					keylen = 128;
				//ci_debug_printf(4, "leaf: select -> key: %s keylen: %i\n", key, keylen);

				licenselen = strlen(licensekey);	
				//ci_debug_printf(4, "leaf: licensekey: %s licenselen: %i\n", licensekey, licenselen);

				xor_encrypt(license.buffer, LSIZE, (unsigned char *)key, keylen);
				xor_encrypt(license.s.key, license.s.keylen, (unsigned char *)licensekey, licenselen);

			        if (license.s.signature == (int32_t)LICENSE_SIGNATURE && !memcmp(license.s.key, key, keylen)) {
					xor_encrypt(license.s.key, license.s.keylen, (unsigned char *)licensekey, licenselen);
					ci_debug_printf(4, "leaf: license signature verified ");
					ci_debug_printf(4, "%02X%02X%02X%02X-%02X%02X%02X%02X-%02X%02X%02X%02X%02X%02X\n",
							license.s.key[0], license.s.key[1], license.s.key[2],
							license.s.key[3], license.s.key[4], license.s.key[5],
							license.s.key[6], license.s.key[7], license.s.key[8],
							license.s.key[9], license.s.key[10], license.s.key[11],
							license.s.key[12], license.s.key[13]);
					fclose(fp);
					update_license_stats(&license);
					return &license;
				}
			}
		}
		fclose(fp);
	}
	ci_debug_printf(4, "leaf: no valid license detected\n");
	return NULL;
}


