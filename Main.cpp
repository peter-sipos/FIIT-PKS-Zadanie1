#define _CRT_SECURE_NO_WARNINGS
#include <pcap.h>
#include <stdio.h>
#define pcap_error_buffer 256
#define max_word_size 26
#define max_ip_string_size 17
#define fragmented_packet 0x999 //pripad trace 26. nie su aj ine packety/protokoly fragmentovane?

// sluzi na dostanie sa pred konkretnu ciselnu hodnotu hladaneho protokolu/portu, aby sa v hlavnej funkcii mohlo dana hodnota v dalsom kroku rovno nacitat
void search_in_file(char *string, FILE *fr) { 
	rewind(fr);
	char str_from_text[max_word_size] = { ' ' };
	while (strcmp(str_from_text, string) != 0)
		fscanf(fr, "%s", str_from_text);
}

void print_frame_number(FILE *f, int *frame_number) {
	(*frame_number)++;
	fprintf(f, "ramec cislo %d\n", *frame_number);
}
void print_frame_number_console(int *frame_number) {
	(*frame_number)++;
	printf("ramec cislo %d\n", *frame_number);
}


void print_frame_length(const struct pcap_pkthdr *frame, FILE *f) {
	fprintf(f, "dlzka ramca poskytnuta pcap APi - %d B\n", frame->caplen);
}
void print_frame_length_console(const struct pcap_pkthdr *frame) {
	printf("dlzka ramca poskytnuta pcap APi - %d B\n", frame->caplen);
}

void print_frame_length_wire(const struct pcap_pkthdr *frame, FILE *f) {
	if (frame->len>=60)
		fprintf(f,"dlzka ramca prenasaneho po mediu - %d B\n", frame->len + 4);
	else
		fprintf(f,"dlzka ramca prenasaneho po mediu - 64 B\n"); // minimalna mozna je z definicie 64B

}
void print_frame_length_wire_console(const struct pcap_pkthdr *frame) {
	if (frame->len >= 60)
		printf("dlzka ramca prenasaneho po mediu - %d B\n", frame->len + 4);
	else
		printf("dlzka ramca prenasaneho po mediu - 64 B\n"); // minimalna mozna je z definicie 64B

}

void print_destaddr(const u_char *data, FILE *f) {
	int pos;
	fprintf(f,"cielova MAC adresa: ");
	for (pos = 0; pos < 6; pos++) {
		fprintf(f,"%.2X ", data[pos]);
	}
	fprintf(f,"\n");
}
void print_destaddr_console(const u_char *data) {
	int pos;
	printf("cielova MAC adresa: ");
	for (pos = 0; pos < 6; pos++) {
		printf("%.2X ", data[pos]);
	}
	printf("\n");
}

void print_srcaddr(const u_char *data, FILE *f) {
	int pos;
	fprintf(f,"zdrojova MAC adresa: ");
	for (pos = 6; pos < 12; pos++) {
		fprintf(f,"%.2X ", data[pos]);
	}
	fprintf(f,"\n");
}
void print_srcaddr_console(const u_char *data) {
	int pos;
	printf("zdrojova MAC adresa: ");
	for (pos = 6; pos < 12; pos++) {
		printf("%.2X ", data[pos]);
	}
	printf("\n");
}

// funckie zistujuce typ prave citaneho ramca
int is_ethernet(const u_char *data, FILE *fr) {
	int first = data[12] << 8, second = data[13], frame, ether_treshold = 0;
	frame = first | second;
	search_in_file("Ethernet_II", fr);
	fscanf(fr, "%X", &ether_treshold); 

	if (frame >= ether_treshold)
		return 1;
	else
		return 0;
}
int is_ieee_raw(const u_char *data, FILE *fr) {
	int first = data[12] << 8, second = data[13], type, is_raw;
	type = first | second;
	search_in_file("IEEE_802.3_Raw", fr); 
	fscanf(fr, "%X", &is_raw);

	if (type == is_raw)
		return 1;
	else
		return 0;
}
int is_ieee_snap(const u_char *data, FILE *fr) {
	int first = data[12] << 8, second = data[13], type, is_snap;
	type = first | second;
	search_in_file("IEEE_802.3_SNAP", fr);
	fscanf(fr, "%X", &is_snap);

	if (type == is_snap)
		return 1;
	else
		return 0;
}

// jednoduche funckcie na zistenie, ci sa v prave citanom ramci nachadza dany protokol/port
int has_ipv4(const u_char *data, FILE *fr) {
	int first = data[12] << 8, second = data[13], is_ip, ip_from_file;
	is_ip = first | second;
	search_in_file("IPv4", fr);
	fscanf(fr, "%X", &ip_from_file);

	if (is_ip == ip_from_file)
		return 1;
	else
		return 0;
}
int has_arp(const u_char *data, FILE *fr) {
	int first = data[12] << 8, second = data[13], arp, arp_from_file;
	arp = first | second;
	search_in_file("ARP", fr);
	fscanf(fr, "%X", &arp_from_file);

	if (arp == arp_from_file)
		return 1;
	else
		return 0;
}
int has_tcp(const u_char *data, FILE *fr) {
	int tcp;
	search_in_file("TCP", fr);
	fscanf(fr, "%X", &tcp);

	if (data[23] == tcp)
		return 1;
	else
		return 0;
}
int has_udp(const u_char *data, FILE *fr) {
	int udp;
	search_in_file("UDP", fr);
	fscanf(fr, "%X", &udp);

	if (data[23] == udp)
		return 1;
	else
		return 0;
}
int has_icmp(const u_char *data, FILE *fr) {
	int icmp;
	search_in_file("ICMP", fr);
	fscanf(fr, "%X", &icmp);

	if (data[23] == icmp)
		return 1;
	else
		return 0;
}


int has_http_dst(const u_char *data, FILE *fr, int *offset) {
	int first = data[36 + (*offset)] << 8, second = data[37 + (*offset)], http, http_from_file;
	http = first | second;
	search_in_file("HTTP", fr);
	fscanf(fr, "%X", &http_from_file);

	if (http == http_from_file)
		return 1;
	else
		return 0;
}
int has_http_src(const u_char *data, FILE *fr, int *offset) {
	int first = data[34 + (*offset)] << 8, second = data[35 + (*offset)], http, http_from_file;
	http = first | second;
	search_in_file("HTTP", fr);
	fscanf(fr, "%X", &http_from_file);

	if (http == http_from_file)
		return 1;
	else
		return 0;
}
int has_http(const u_char *data, FILE *fr, int *offset) {
	if (has_http_dst(data, fr, offset) || has_http_src(data, fr, offset))
		return 1;
	else 
		return 0;
}


int has_https_src(const u_char *data, FILE *fr, int *offset) {
	int first = data[34 + (*offset)] << 8, second = data[35 + (*offset)], https, https_from_file;
	https = first | second;
	search_in_file("HTTPS", fr);
	fscanf(fr, "%X", &https_from_file);

	if (https == https_from_file)
		return 1;
	else
		return 0;
}
int has_https_dst(const u_char *data, FILE *fr, int *offset) {
	int first = data[36 + (*offset)] << 8, second = data[37 + (*offset)], https, https_from_file;
	https = first | second;
	search_in_file("HTTPS", fr);
	fscanf(fr, "%X", &https_from_file);

	if (https == https_from_file)
		return 1;
	else
		return 0;
}
int has_https(const u_char *data, FILE *fr, int *offset) {
	if (has_https_dst(data, fr, offset) || has_https_src(data, fr, offset))
		return 1;
	else
		return 0;
}


int has_ftp_data_src(const u_char *data, FILE *fr, int *offset) {
	int first = data[34 + (*offset)] << 8, second = data[35 + (*offset)], ftp_data, ftp_data_from_file;
	ftp_data = first | second;
	search_in_file("FTP_DATA", fr);
	fscanf(fr, "%X", &ftp_data_from_file);

	if (ftp_data == ftp_data_from_file)
		return 1;
	else
		return 0;
}
int has_ftp_data_dst(const u_char *data, FILE *fr, int *offset) {
	int first = data[36 + (*offset)] << 8, second = data[37 + (*offset)], ftp_data, ftp_data_from_file;
	ftp_data = first | second;
	search_in_file("FTP_DATA", fr);
	fscanf(fr, "%X", &ftp_data_from_file);

	if (ftp_data == ftp_data_from_file)
		return 1;
	else
		return 0;
}
int has_ftp_data(const u_char *data, FILE *fr, int *offset) {
	if (has_ftp_data_dst(data, fr, offset) || has_ftp_data_src(data, fr, offset))
		return 1;
	else
		return 0;
}


int has_ftp_control_src(const u_char *data, FILE *fr, int *offset) {
	int first = data[34 + (*offset)] << 8, second = data[35 + (*offset)], ftp_control, ftp_control_from_file;
	ftp_control = first | second;
	search_in_file("FTP_CONTROL", fr);
	fscanf(fr, "%X", &ftp_control_from_file);

	if (ftp_control == ftp_control_from_file)
		return 1;
	else
		return 0;
}
int has_ftp_control_dst(const u_char *data, FILE *fr, int *offset) {
	int first = data[36 + (*offset)] << 8, second = data[37 + (*offset)], ftp_control, ftp_control_from_file;
	ftp_control = first | second;
	search_in_file("FTP_CONTROL", fr);
	fscanf(fr, "%X", &ftp_control_from_file);

	if (ftp_control == ftp_control_from_file)
		return 1;
	else
		return 0;
}
int has_ftp_control(const u_char *data, FILE *fr, int *offset) {
	if (has_ftp_control_dst(data, fr, offset) || has_ftp_control_src(data, fr, offset))
		return 1;
	else
		return 0;
}


int has_ssh_src(const u_char *data, FILE *fr, int *offset) {
	int first = data[34 + (*offset)] << 8, second = data[35 + (*offset)], protocol, protocol_from_file;
	protocol = first | second;
	search_in_file("SSH", fr);
	fscanf(fr, "%X", &protocol_from_file);

	if (protocol == protocol_from_file)
		return 1;
	else
		return 0;
}
int has_ssh_dst(const u_char *data, FILE *fr, int *offset) {
	int first = data[36 + (*offset)] << 8, second = data[37 + (*offset)], protocol, protocol_from_file;
	protocol = first | second;
	search_in_file("SSH", fr);
	fscanf(fr, "%X", &protocol_from_file);

	if (protocol == protocol_from_file)
		return 1;
	else
		return 0;
}
int has_ssh(const u_char *data, FILE *fr, int *offset) {
	if (has_ssh_dst(data, fr, offset) || has_ssh_src(data, fr, offset))
		return 1;
	else
		return 0;
}


int has_telnet_src(const u_char *data, FILE *fr, int *offset) {
	int first = data[34 + (*offset)] << 8, second = data[35 + (*offset)], protocol, protocol_from_file;
	protocol = first | second;
	search_in_file("TELNET", fr);
	fscanf(fr, "%X", &protocol_from_file);

	if (protocol == protocol_from_file)
		return 1;
	else
		return 0;
}
int has_telnet_dst(const u_char *data, FILE *fr, int *offset) {
	int first = data[36 + (*offset)] << 8, second = data[37 + (*offset)], protocol, protocol_from_file;
	protocol = first | second;
	search_in_file("TELNET", fr);
	fscanf(fr, "%X", &protocol_from_file);

	if (protocol == protocol_from_file)
		return 1;
	else
		return 0;
}
int has_telnet(const u_char *data, FILE *fr, int *offset) {
	if (has_telnet_dst(data, fr, offset) || has_telnet_src(data, fr, offset))
		return 1;
	else
		return 0;
}


int has_tftp_src(const u_char *data, FILE *fr, int *offset) {
	int first = data[34 + (*offset)] << 8, second = data[35 + (*offset)], protocol, protocol_from_file;
	protocol = first | second;
	search_in_file("TFTP", fr);
	fscanf(fr, "%X", &protocol_from_file);

	if (protocol == protocol_from_file)
		return 1;
	else
		return 0;
}
int has_tftp_dst(const u_char *data, FILE *fr, int *offset) {
	int first = data[36 + (*offset)] << 8, second = data[37 + (*offset)], protocol, protocol_from_file;
	protocol = first | second;
	search_in_file("TFTP", fr);
	fscanf(fr, "%X", &protocol_from_file);

	if (protocol == protocol_from_file)
		return 1;
	else
		return 0;
}
int has_tftp(const u_char *data, FILE *fr, int *offset) {
	if (has_tftp_dst(data, fr, offset) || has_tftp_src(data, fr, offset))
		return 1;
	else
		return 0;
}


int has_tftp_estabilished_src(const u_char *data, int *tftp, int *offset) {
	int first = data[34 + (*offset)] << 8, second = data[35 + (*offset)], protocol;
	protocol = first | second;
	if (protocol == *tftp)
		return 1;
	else
		return 0;
}
int has_tftp_estabilished_dst(const u_char *data, int *tftp, int *offset) {	
	int first = data[36 + (*offset)] << 8, second = data[37 + (*offset)], protocol;
	protocol = first | second;
	if (protocol == *tftp)
		return 1;
	else
		return 0;
}
int has_tftp_estabilished(const u_char *data, int *tftp, int *offset) {
	if (has_tftp_estabilished_src(data, tftp, offset) || has_tftp_estabilished_dst(data, tftp, offset))
		return 1;
	else
		return 0;
}

void determine_frame(const u_char *data, FILE *fw, FILE *fr) {
	if(is_ethernet(data, fr))
		fprintf(fw,"Ethernet 2\n");
	else if (is_ieee_raw(data, fr))
		fprintf(fw,"IEEE 802.3 - RAW\n");
	else if (is_ieee_snap(data, fr))
		fprintf(fw,"IEEE 802.3 - SNAP\n");
	else
		fprintf(fw,"IEEE 802.3 - LLC\n");
}
void determine_frame_console(const u_char *data, FILE *fr) {
	if (is_ethernet(data, fr))
		printf("Ethernet 2\n");
	else if (is_ieee_raw(data, fr))
		printf("IEEE 802.3 - RAW\n");
	else if (is_ieee_snap(data, fr))
		printf("IEEE 802.3 - SNAP\n");
	else
		printf("IEEE 802.3 - LLC\n");
}

// vypise cely ramec v hexadecimalnom formate
void print_hexagulash(const u_char *data, const struct pcap_pkthdr *pkthdr, FILE *f) {
	for (unsigned int iter = 0; iter < pkthdr->caplen; iter++) {
		if (iter % 8 == 0 && iter!= 0)
			fprintf(f,"  ");
		if (iter % 16 == 0 && iter!= 0)
			fprintf(f,"\n");
		fprintf(f,"%.2X ", data[iter]);
	}
	fprintf(f,"\n");
}
void print_hexagulash_console(const u_char *data, const struct pcap_pkthdr *pkthdr) {
	for (unsigned int iter = 0; iter < pkthdr->caplen; iter++) {
		if (iter % 8 == 0 && iter != 0)
			printf("  ");
		if (iter % 16 == 0 && iter != 0)
			printf("\n");
		printf("%.2X ", data[iter]);
	}
	printf("\n");
}

void packet_to_do(u_char *frame_number, const struct pcap_pkthdr *pkthdr, const u_char *data) {
	FILE *fw = fopen("vypis_pcap_suboru.txt", "a");
	FILE *fr = fopen("what_is_what.txt", "r");
	print_frame_number(fw, (int*)frame_number);
	print_frame_length(pkthdr,fw);
	print_frame_length_wire(pkthdr,fw);
	determine_frame(data,fw, fr);
	print_srcaddr(data,fw);
	print_destaddr(data,fw);
	print_hexagulash(data, pkthdr,fw);
	fprintf(fw, "\n");
	fclose(fw);
	fclose(fr);
}

// vypise vsetky komunikujuce uzly, k uzlu s najvacsim poctom odoslanych bajtov napise kolko sa odoslalo
void print_ips(pcap_t *pcap_file, FILE *fw, FILE *fr, char *file_name) {
	struct pcap_pkthdr *header;
	const u_char *data;
	int ips_count = 0, **ips_arr, i, j, ipMax = 0, ipMax_in = 0;
	char error_buffer[pcap_error_buffer];

	pcap_file = pcap_open_offline(file_name, error_buffer);

	fprintf(fw, "IP adresy vysielajucich uzlov:\n"); 
	while (pcap_next_ex(pcap_file, &header, &data) >= 0) {
		if (has_ipv4(data, fr)) {
			ips_count++;
		}
	}

	ips_arr = (int**)malloc(ips_count * sizeof(int*)); //inicializujem 2d pole
	for (i = 0; i < ips_count; i++) {
		ips_arr[i] = (int*)malloc(5*sizeof(int));
	}
	for (i = 0; i < ips_count; i++) {
		for(j=0; j<5; j++)
		ips_arr[i][j] = 0; 
	}
	
	i = 0;
	int first, second, first_half, second_half;
	pcap_file = pcap_open_offline(file_name, error_buffer);

	while (pcap_next_ex(pcap_file, &header, &data) >= 0 && i<ips_count) { 
		for (j = 0; j < i; j++) { // prejdi vsetky ipcky od zaciatku
		 //ak sa uz dana ipcka nasla tak iba pripocitaj jej velkost
			if(ips_arr[j][0] == data[26] && ips_arr[j][1] == data[27] && ips_arr[j][2] == data[28] && ips_arr[j][3] == data[29]){
				if (header->len >= 60)
					ips_arr[j][4] += header->len + 4;
				else
					ips_arr[j][4] += 64;
				break;
				i++;
			}
		}

		if (j == i) { //j==i vtedy, ked sa horny for nebreakol a teda sa nenasla zhodna ipcka. ak by sa totiz nasla, tak by j != i
			ips_arr[j][0] = data[26];
			ips_arr[j][1] = data[27];
			ips_arr[j][2] = data[28];
			ips_arr[j][3] = data[29];
			fprintf(fw, "%d.%d.%d.%d\n", data[26], data[27], data[28], data[29]);

			if (header->len >= 60)
				ips_arr[j][4] += header->len + 4;
			else
				ips_arr[j][4] += 64;
			i++;
		}				
	}

	for (i = 0; i < ips_count; i++) { //najdenie maximalneho poctu odoslanych dat
		if (ips_arr[i][4] > ipMax) {
			ipMax = ips_arr[i][4];
			ipMax_in = i;
		}
	}

	fprintf(fw, "\nAdresa uzla s najvacsim poctom odvysielanych bajtov:\n");
	fprintf(fw, "%d.%d.%d.%d    %d\n",
		ips_arr[ipMax_in][0], ips_arr[ipMax_in][1], ips_arr[ipMax_in][2], ips_arr[ipMax_in][3], ipMax);
}

void print_tcp_console(const u_char *data, int *offset) {
	int src_first = data[34 + (*offset)] << 8, src_second = data[35 + (*offset)], src;
	src = src_first | src_second;
	printf("TCP\n");
	printf("zdrojovy port: %d\n", src);
	int dst_first = data[36 + (*offset)] << 8, dst_second = data[37 + (*offset)], dst; 
	dst = dst_first | dst_second;
	printf("cielovy port: %d\n", dst);
}
void print_udp_console(const u_char *data, int *offset) {
	int src_first = data[34 + (*offset)] << 8, src_second = data[35 + (*offset)], src;
	src = src_first | src_second;
	printf("UDP\n");
	printf("zdrojovy port: %d\n", src);
	int dst_first = data[36 + (*offset)] << 8, dst_second = data[37 + (*offset)], dst;  
	dst = dst_first | dst_second;
	printf("cielovy port: %d\n", dst);
}
void print_ip(const u_char *data, FILE *fw) {
	fprintf(fw, "IPv4\n");
	fprintf(fw, "zdrojova IP adresa: %d.%d.%d.%d\n", data[26], data[27], data[28], data[29]);
	fprintf(fw, "cielova IP adresa: %d.%d.%d.%d\n", data[30], data[31], data[32], data[33]);
}
void print_ip_console(const u_char *data) {
	printf("IPv4\n");
	printf("zdrojova IP adresa: %d.%d.%d.%d\n", data[26], data[27], data[28], data[29]);
	printf("cielova IP adresa: %d.%d.%d.%d\n", data[30], data[31], data[32], data[33]);
}

void print_tcp_com_console(FILE *fr, int *frame_number, struct pcap_pkthdr *pkthdr, const u_char *data, int *offset) {
	print_frame_number_console(frame_number);
	print_frame_length_console(pkthdr);				
	print_frame_length_wire_console(pkthdr);
	determine_frame_console(data, fr);
	print_srcaddr_console(data);
	print_destaddr_console(data);
	print_ip_console(data);
	print_tcp_console(data, offset);
	print_hexagulash_console(data, pkthdr);
	printf("\n");
}

void print_icmp_console(const u_char *data, FILE *fr, int *offset) {
	printf("ICMP type: ");
	//nacitaj z pozicie typu, prehladavaj v subore kym nenarazis na danu hodnotu, potom vypis dany typ
	rewind(fr);
	int type_from_file = -1, type;
	type = data[34 + (*offset)];
	while (type != type_from_file && type_from_file != fragmented_packet)	
		fscanf(fr, "%*s %X", &type_from_file);
	char type_of_icmp[max_word_size];
	fscanf(fr, "%s", type_of_icmp);
	printf("%s\n", type_of_icmp);
}
void print_icmp_com_console(FILE *fr, int *frame_number, struct pcap_pkthdr *pkthdr, const u_char *data, int *offset) {
	print_frame_number_console(frame_number);
	print_frame_length_console(pkthdr);
	print_frame_length_wire_console(pkthdr);
	determine_frame_console(data, fr);
	print_srcaddr_console(data);
	print_destaddr_console(data);
	print_ip_console(data);
	print_icmp_console(data, fr, offset);
	print_hexagulash_console(data, pkthdr);
	printf("\n");
}

void print_tftp_console(FILE *fr, int *frame_number, struct pcap_pkthdr *pkthdr, const u_char *data, int *offset) {
	print_frame_number_console(frame_number);
	print_frame_length_console(pkthdr);
	print_frame_length_wire_console(pkthdr);
	determine_frame_console(data, fr);
	print_srcaddr_console(data);
	print_destaddr_console(data);
	print_ip_console(data);
	print_udp_console(data, offset);
	print_hexagulash_console(data, pkthdr);
	printf("\n");
}

void print_arp_request_console(FILE *fr, int *frame_number, int *arp_com_counter, char *target_ip, struct pcap_pkthdr *pkthdr, const u_char *data) {
	char ip_string[max_ip_string_size];
	sprintf(ip_string, "%d.%d.%d.%d", data[38], data[39], data[40], data[41]);
	if(strcmp(target_ip, ip_string)!=0){
		printf("Komunikacia c. %d\n", *arp_com_counter);
		(*arp_com_counter)++;
	}
	strcpy(target_ip, ip_string);
	printf("ARP-Request, IP adresa: %d.%d.%d.%d, MAC adresa: ???\n", data[38], data[39], data[40], data[41]); 
	printf("Zdrojova IP: %d.%d.%d.%d,  Cielova IP: %d.%d.%d.%d\n", data[28], data[29], data[30], data[31], data[38], data[39], data[40], data[41]);
	print_frame_number_console(frame_number);
	print_frame_length_console(pkthdr);
	print_frame_length_wire_console(pkthdr);
	determine_frame_console(data, fr);
	print_srcaddr_console(data);
	print_destaddr_console(data);
	print_hexagulash_console(data, pkthdr);
	printf("\n");
}
void print_arp_reply_console(FILE *fr, int *frame_number, struct pcap_pkthdr *pkthdr, const u_char *data) {
	printf("ARP-Reply, IP adresa: %d.%d.%d.%d, MAC adresa: %.2X %.2X %.2X %.2X %.2X %.2X\n", data[28], data[29], data[30], data[31], data[22], data[23], data[24], data[25], data[26], data[27]); 
	printf("Zdrojova IP: %d.%d.%d.%d,  Cielova IP: %d.%d.%d.%d\n", data[28], data[29], data[30], data[31], data[38], data[39], data[40], data[41]);
	print_frame_number_console(frame_number);
	print_frame_length_console(pkthdr);
	print_frame_length_wire_console(pkthdr);
	determine_frame_console(data, fr);
	print_srcaddr_console(data);
	print_destaddr_console(data);
	print_hexagulash_console(data, pkthdr);
	printf("\n");
}
int is_arp_request(FILE *fr, const u_char *data) {
	int request;
	search_in_file("Request", fr);
	fscanf(fr, "%d", &request);
	if (data[21] == request)
		return 1;
	else
		return 0;
}

// vypise konkretnu komunikaciu hladanu pouzivatelom
void print_exac_com(pcap_t *pcap_file, FILE *fw, FILE *fr, char *file_name, char *com) {
	struct pcap_pkthdr *header;
	const u_char *data;
	char error_buffer[pcap_error_buffer], target_ip[max_ip_string_size] = { ' ' };
	pcap_file = pcap_open_offline(file_name, error_buffer);
	int frame_number = 0, com_amount = 0, com_counter = 0;
	int arp_com_counter = 1, arp_new = 1, tftp_established = 0, first, second, offset =0, vhl;

	//spocita pocet vypisov
	while (pcap_next_ex(pcap_file, &header, &data) >= 0) {
		if (!is_ethernet(data, fr)) {
			continue;
		}
		if (has_ipv4(data, fr)) { 

			// ak je velkost IP hlavicky vacsia ako 5, tak si vypocita "offset" o kolko bajtov je nasledujuci protokol posunuty oproti tomu, keby velkost bola 5
			vhl = data[14];
			offset = ((vhl % (4 * 16)) - 5) * 4;

			if (has_tcp(data, fr)) {
				if (strcmp(com, "FTP_DATA") == 0)
					if (has_ftp_data(data, fr, &offset)) {
						com_amount++;
					}
				if (strcmp(com, "FTP_CONTROL") == 0)
					if (has_ftp_control(data, fr, &offset)) {
						com_amount++;
					}
				if (strcmp(com, "SSH") == 0)
					if (has_ssh(data, fr, &offset)) {
						com_amount++;
					}
				if (strcmp(com, "TELNET") == 0)
					if (has_telnet(data, fr, &offset)) {
						com_amount++;
					}
				if (strcmp(com, "HTTP") == 0)
					if (has_http(data, fr, &offset)) {
						com_amount++;
					}
				if (strcmp(com, "HTTPS") == 0)
					if (has_https(data, fr, &offset)) {
						com_amount++;
					}
			}

			if (strcmp(com, "ICMP") == 0)
				if (has_icmp(data, fr)) {
					com_amount++;
				}

			if (has_udp(data, fr)) {
				if (strcmp(com, "TFTP") == 0)
					if (has_tftp(data, fr, &offset)) {
						com_amount++;
						first = data[34] << 8;
						second = data[35];
						tftp_established = first | second; // ulozi si novy port, na ktorom bude TFTP dalej komunikovat
						continue;
					}
					else if (has_tftp_estabilished(data, &tftp_established, &offset))
						com_amount++;
			}
		}

		if (strcmp(com, "ARP") == 0)
			if (has_arp(data, fr)) {
				com_amount++;
			}
	} 

	pcap_file = pcap_open_offline(file_name, error_buffer);
	frame_number = 0;
	printf("com amount je %d\n", com_amount);
	//vypis
	while (pcap_next_ex(pcap_file, &header, &data) >= 0) {
		if (!is_ethernet(data, fr)) {
			frame_number++;
			continue;
		}

		if (has_ipv4(data, fr)) {
			vhl = data[14];
			offset = ((vhl % (4 * 16)) - 5) * 4;

			if (has_tcp(data, fr)) {
				if (strcmp(com, "FTP_DATA") == 0)
					if (has_ftp_data(data, fr, &offset)) {
						if (com_counter < 10 || com_counter >= com_amount - 10) { // vypis iba prvych a poslednych 10
							printf("FTP_DATA\n");
							print_tcp_com_console(fr, &frame_number, header, data, &offset);
						}
						else
							frame_number++; 
						com_counter++;
						continue;
					}
						
				if (strcmp(com, "FTP_CONTROL") == 0)
					if (has_ftp_control(data, fr, &offset)) {
						if (com_counter < 10 || com_counter >= com_amount - 10) {
							printf("FTP_CONTROL\n");
							print_tcp_com_console(fr, &frame_number, header, data, &offset);
						}
						else
							frame_number++;
						com_counter++;
						continue;
					}
						
				if (strcmp(com, "SSH") == 0)
					if (has_ssh(data, fr, &offset)) {
						if (com_counter < 10 || com_counter >= com_amount - 10) {
							printf("SSH\n");
							print_tcp_com_console(fr, &frame_number, header, data, &offset);
						}
						else
							frame_number++;
						com_counter++;
						continue;
					}
						
				if (strcmp(com, "TELNET") == 0)
					if (has_telnet(data, fr, &offset)) {
						if (com_counter < 10 || com_counter >= com_amount - 10) {
							printf("TELNET\n");
							print_tcp_com_console(fr, &frame_number, header, data, &offset);
						}
						else
							frame_number++;
						com_counter++;
						continue;
					}
						
				if (strcmp(com, "HTTP") == 0)
					if (has_http(data, fr, &offset)) {
						if (com_counter < 10 || com_counter >= com_amount - 10) {
							printf("HTTP\n");
							print_tcp_com_console(fr, &frame_number, header, data, &offset);
						}
						else
							frame_number++;
						com_counter++;
						continue;
					}
						
				if (strcmp(com, "HTTPS") == 0)
					if (has_https(data, fr, &offset)) {
						if (com_counter < 10 || com_counter >= com_amount - 10) {
							printf("HTTPS\n");
							print_tcp_com_console(fr, &frame_number, header, data, &offset);
						}
						else
							frame_number++;
						com_counter++;
						continue;
					}
			}

			if (strcmp(com, "ICMP") == 0)
				if (has_icmp(data, fr)) {
					if (com_counter < 10 || com_counter >= com_amount - 10) {
						printf("ICMP\n");
						print_icmp_com_console(fr, &frame_number, header, data, &offset);
					}
					else
						frame_number++;
					com_counter++;
					continue;
				}

			if (has_udp(data, fr)) {
				if (strcmp(com, "TFTP") == 0)
					if (has_tftp(data, fr, &offset)) {
						if (com_counter < 10 || com_counter >= com_amount - 10) {
							printf("TFTP\n");
							print_tftp_console(fr, &frame_number, header, data, &offset);
						}
						else
							frame_number++;
						first = data[34] << 8;
						second = data[35];
						tftp_established = first | second;
						com_counter++;
						continue;
					}
					else if (has_tftp_estabilished(data, &tftp_established, &offset)) {
						if (com_counter < 10 || com_counter >= com_amount - 10) {
							printf("TFTP\n");
							print_tftp_console(fr, &frame_number, header, data, &offset);
						}
 						else
							frame_number++;
						com_counter++;
						continue;
					}

			}
		}

		if (strcmp(com, "ARP") == 0)
			if (has_arp(data, fr)) {
				if (is_arp_request(fr, data))
					if(com_counter < 10 || com_counter >= com_amount - 10)
						print_arp_request_console(fr, &frame_number, &arp_com_counter, target_ip, header, data);
					else
						frame_number++;
				else
					if (com_counter < 10 || com_counter >= com_amount - 10)
						print_arp_reply_console(fr, &frame_number, header, data);
					else
						frame_number++;
				com_counter++;
				continue;
			}
		frame_number++;
	}
}


int is_unreachable(const u_char *data, int *offset) {
	int type = data[34 + (*offset)];
	if (type == 0x3)
		return 1;
	else 
		return 0;
}
void print_icmp_unreachable(const u_char *data, int *frame_number, FILE *fw, int *counter, FILE *fr, struct pcap_pkthdr *pkthdr) {
	int vhl, offset;
	if(is_ethernet(data, fr))
		if (has_ipv4(data, fr)) {
			vhl = data[14];
			offset = ((vhl % (4 * 16)) - 5) * 4;

			if (has_icmp(data, fr))
				if (is_unreachable(data, &offset)) {
					print_frame_number(fw, frame_number);
					print_hexagulash(data, pkthdr, fw);
					fprintf(fw, "tento ramec je ICMP destination unreachable\n");
					(*counter)++;
					return;
				}
		}
	(*frame_number)++;
}

int main() {
	FILE *fw = fopen("vypis_pcap_suboru.txt", "w");		//premaze subor ak uz nahodou existoval z minuleho pustenia
	fclose(fw);

	char error_buffer[pcap_error_buffer], file_name[2000], com_name[max_word_size];
	int frame_number = 0;
	pcap_t *pcap_file;

	scanf("%s", &file_name);
	pcap_file = pcap_open_offline(file_name, error_buffer);
	if (pcap_file == NULL) {
		printf("nieco se pokazilo (zrejme ste zadali neplatnu cestu k .pcap suboru). tu je o to sprava: %s\n", &error_buffer);
		return 2;
	}

	pcap_loop(pcap_file, 0, packet_to_do, (u_char*)&frame_number);

	fw = fopen("vypis_pcap_suboru.txt", "a");
	FILE *fr = fopen("what_is_what.txt", "r");
	print_ips(pcap_file, fw, fr, file_name);
	printf("vypis vsetkych ramcov bol zaznamenany do suboru\n");

	pcap_file = pcap_open_offline(file_name, error_buffer);
	struct pcap_pkthdr *header;
	const u_char *data;
	int unreachable_counter = 0;
	frame_number = 0;
	FILE *fx = fopen("icmp_uncreachable.txt", "w");
	while (pcap_next_ex(pcap_file, &header, &data) >= 0) {
		print_icmp_unreachable(data, &frame_number, fx, &unreachable_counter, fr, header);
	}
	printf("v danom subore je tolkoto icmp_unreachable %d\n", unreachable_counter);


	printf("\nchcete vypisat nejaku konkretnu komunikaciu? ak nie, zadajte 'n'\n");
	printf("ak ano, tak napiste jej nazov v tvare uvedenom nizsie. komunikacie, ktore sa daju vypisat:\n");
	printf("ARP, ICMP, FTP_DATA, FTP_CONTROL, SSH, TELNET, HTTP, HTTPS, TFTP\n\n");
	scanf("%s", com_name); 
	printf("\n");
	while (strcmp(com_name, "n") != 0) {
		print_exac_com(pcap_file, fw, fr, file_name, com_name);
		printf("\nchcete vypisat dalsiu komunikaciu? ak nie, zadajte 'n'\n");
		printf("ak ano, tak napiste jej nazov v tvare uvedenom nizsie. komunikacie, ktore sa daju vypisat:\n");
		printf("ARP, ICMP, FTP_DATA, FTP_CONTROL, SSH, TELNET, HTTP, HTTPS, TFTP\n\n");
		scanf("%s", com_name);
		printf("\n");
	}

	pcap_close(pcap_file);
	fclose(fw);
	fclose(fr);
	return 0;
}