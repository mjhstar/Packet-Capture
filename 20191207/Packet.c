
//#define HAVE_REMOTE
//#include "stdafx.h"
//#define _CRT_SECURE_NO_WARNINGS    // fopen ���� ���� ���� ������ ���� ����
#include "pcap.h"

#include <WinSock2.h>

#pragma comment(lib, "ws2_32.lib")
#define GETPACKETNUMBER 0
int packetCountNum=0;
char tempBuf[200] = { 0, };
char fileName[200] = { 0, };

char addTxt[5] = ".txt";
FILE* fp = NULL;

void packet_handler(u_char* param, const struct pcap_pkthdr* h, const u_char* data);
//��Ŷ�� ���� ���� ���¿��� �а� ó���ϴ� �Լ�

typedef struct Ethernet_Header//�̴��� ��� ����ü
{
	u_char des[6];//������ MAC �ּ�
	u_char src[6];//�۽��� MAC �ּ�
	short int ptype;//�ڿ� ���� ��Ŷ�� �������� ����(��:ARP/IP/RARP)
			//IP ����� ���� ��� : 0x0800
			//ARP ����� ���� ��� : 0x0806
			//RARP ����� ���� ��� : 0x0835
}Ethernet_Header;//�θ� �̸� ����(����)

typedef struct ipaddress
{
	u_char ip1;
	u_char ip2;
	u_char ip3;
	u_char ip4;
}ip;

//IP ���������� ����� ������ ����ü ����
typedef struct IPHeader
{
	u_char HeaderLength : 4;//��� ���� *4
	u_char Version : 4;//IP v4 or IPv6
	u_char TypeOfService;//���� ����
	u_short TotalLength;//��� ���� + ������ ����/
	u_short ID;//������ ��Ʈ�� Identification
	u_short FlagOffset;//�÷��� + �����׸�Ʈ ������

	u_char TimeToLive;//TimeToL, TTL
	u_char Protocol;//�������� ����(1. ICMP  2. IGMP  6. TCP 17. UDP;
	u_short checksum;

	ip SenderAddress;
	//ipaddress SenderAddress;
	ip DestinationAddress;
	//ipaddress DestinationAddress;
	u_int Option_Padding;

}IPHeader;


typedef struct CheckSummer
{
	//0    2byte       2byte   32
	// [   4500   ][   003c   ] Version, HeaderLength, TypeOfService / TotalLength
	// [   11e5   ][   0000   ] Identification / Flag, FragmentOffset
	// [   8001   ][          ] TimeToLive, Protocol / HeaderChecksum
	// [   7c89   ][   19a4   ] Source Address
	// [   7c89   ][   19a3   ] Destination Address
	// �� ��� ������ ���� HeaderChecksum ���� ���� ���, ��Ŷ�� �����̴�.
	// �׷��� �� ���ϸ� 2037b �� 2����Ʈ ũ�⸦ �Ѱ� �ȴ�.
	// �׷��� �� 037b�� ������ ���� �÷ο� �� 2�� �ڿ� ���Ѵ�.
	//     037b
	//  +     2
	//  ��������
	//     037d
	// �׸��� ���� ��� ��� ��(037d)�� ���� ���·� ���Ѵ�.
	// (1�� ���� = 0�� 1��, 1�� 0����)
	// 037d = 0000 0011 0111 1101
	// ���� = 1111 1100 1000 0010
	// 16�� = fc82
	// �׷��Ƿ� ����� �κп��� fc82�� ���� �ȴ�.

	/*
	u_char = 1 byte
	u_short = 2 byte
	int = 4 byte
	*/
	//������ ���� ������ Version�� ��� ���� �������� �޾ƾ� ���������� ��� ���̿� ������ ���´�.
	/*
	u_char = 1 byte
	u_short = 2 byte
	int = 4 byte
	*/
	u_short part1;
	u_short part2;
	u_short part3;
	u_short part4;
	u_short part5;
	u_short checksum;
	u_short part6;
	u_short part7;
	u_short part8;
	u_short part9;

}CheckSummer;

void main()
{
	//���� ����
	printf("������ ������ �̸��� �ۼ����ּ���(������ txt���Ϸ� ����˴ϴ�. Ȯ���ڴ� ���� �ʾƵ� �˴ϴ�.):");
	gets_s(fileName, sizeof(fileName)); //������ ������ ���� �̸� �Է��� ��
	strcat(fileName, addTxt); //���� �̸��� txt Ȯ���� ��ġ��
	fp= fopen(fileName, "w");



	pcap_if_t* allDevice; //ã�Ƴ� ����̽��� LinkedList�� ����, �� �� ù ��° ������Ʈ�� ���� ���� ����
	pcap_if_t* device; //Linked List�� ���� ������Ʈ�� ���� ����
	char errorMSG[256]; //���� �޽����� ���� ���� ����
	//char counter = 0; //������ ����

	pcap_t* pickedDev; //����� ����̽��� �����ϴ� ����

					   //1. ��ġ �˻� (ã�Ƴ� ����̽��� LinkedList�� ����)
	if ((pcap_findalldevs(&allDevice, errorMSG)) == -1)//���� �����ÿ��� 1 ����������, pcap_findalldev�� ���°� ���� ����Ʈ�̹Ƿ� �ּҷ� �־�� ��.
													   //pcap_if_t�� int���¸� ��ȯ�ϸ�, -1�� ���� ���, ����̽��� ã�� ������ ����̴�.
		printf("��ġ �˻� ����");

	//2. ��ġ ���
	int count = 0;
	for (device = allDevice; device != NULL; device = device->next)
		//dev�� allDevice�� ù ���� �ּҸ� ������, device�� ���� NULL(��)�� ��� ����, dev�� �� for���� ���� �ּҰ����� ��ȯ
	{
		printf(" %d �� ��Ʈ��ũ ī�妡����������������������������������������������������\n", count);
		printf("������� ���� : %s\n", device->name);
		printf("������� ���� : %s\n", device->description);
		printf("��������������������������������������������������������������������������\n");
		count = count +1;

	}

	//3. ��Ʈ��ũ ī�带 �����ϰ� ���õ� ����̽��� ������ ��Ŷ �����ϱ�
	printf("��Ŷ�� ������ ��Ʈ��ũ ī�带 ���� �ϼ��� : ");
	device = allDevice;//ī�带 �������� �ʰ� �׳� ù ��° ī��� ��������.

	int choice;
	scanf_s("%d", &choice);
	for (count = 0; count < choice; count++)
	{
		device = device->next;
	}

	//��Ʈ��ũ ��ġ�� ����, ������ ��Ŷ ���� �����Ѵ�.
	pickedDev = pcap_open_live(device->name, 65536, 1, 1000, errorMSG);
	//��ī���� �̸�, ������ ��Ŷ ũ��(�ִ� 65536), ���ι̽�ť����(��Ŷ ���� ���) ����, ��Ŷ ��� �ð�, ���� ������ ������ ����)

	//4. ��ī�� ����Ʈ ������ ������ �޸𸮸� ����ش�.
	pcap_freealldevs(allDevice);

	//5. ������ ��Ʈ��ũ ī�忡�� ��Ŷ�� ���� ĸ�� �� �Լ��� ����� ĸ�ĸ� �����Ѵ�.
	pcap_loop(pickedDev, GETPACKETNUMBER, packet_handler, NULL);
	
	sprintf(tempBuf, "�˻��� ��Ŷ ���� : %d ���Դϴ�. \n", packetCountNum);
	printf("%s", tempBuf);
	fwrite(tempBuf, strlen(tempBuf), 1, fp);

	fclose(fp);

}


//�Ʒ����� ����� �� �ֵ�����Ŷ �ڵ鷯�� �����.
void packet_handler(u_char* param, const struct pcap_pkthdr* h, const u_char* data)
//���� = �Ķ����, ��Ŷ ���, ��Ŷ ������(������ MAC �ּ� �κ� ����)
{
#define IPHEADER 0x0800
#define ARPHEADER 0x0806
#define RARPHEADER 0x0835
	//�ҽ� ���� �� �������� ���� ����� ���ڷ� �ٲ۴�.

	

	Ethernet_Header* EH = (Ethernet_Header*)data;//data �ּҿ� ����� 14byte �����Ͱ� ����ü Ethernet_Header ���·� EH�� ����ȴ�.
	short int type = ntohs(EH->ptype);
	//EH->ptype�� �� ����� ������ ���ϹǷ�,
	//�̸� ��Ʋ ����� �������� ��ȯ(ntohs �Լ�)�Ͽ� type�� �����Ѵ�.
	
	sprintf(tempBuf, "���� ��Ŷ : %04x\n", EH->ptype);
	printf("%s", tempBuf);
	fwrite(tempBuf, strlen(tempBuf), 1, fp);
	
	//�������� �׳� ��Ʈ��ũ�� ���� 1����Ʈ�� �ʰ��ϴ� �����͸�
	//���� ���� ����  �׻� ��Ʋ ����� �������� ��ȯ �� �־�� �Ѵٰ� �ܿ���.
	sprintf(tempBuf, "����������������������������������������������������\n");
	printf("%s", tempBuf);
	fwrite(tempBuf, strlen(tempBuf), 1, fp);

	sprintf(tempBuf,"�� Src MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->src[0], EH->src[1], EH->src[2], EH->src[3], EH->src[4], EH->src[5]);//�۽��� MAC
	printf("%s", tempBuf);
	fwrite(tempBuf, strlen(tempBuf), 1, fp);

	sprintf(tempBuf,"�� Dst MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->des[0], EH->des[1], EH->des[2], EH->des[3], EH->des[4], EH->des[5]);//������ MAC
	printf("%s", tempBuf);
	fwrite(tempBuf, strlen(tempBuf), 1, fp);
	IPHeader* IH = (struct IPHeader*)(data + 14); //���� ó�� 14byte�� �̴��� ���(Layer 2) �� ������ IP���(20byte), �� ������ TCP ���...
	CheckSummer* CS = (struct CheckSummer*)(data + 14); //üũ���� ���� �� ����
	//���� ������ 01010101�̹Ƿ� ������ �ڸ���� ���ص� ��.
	//����� �ٴ� Layer2�� �����͸�ũ �������� �ڸ��� ��.
	if (type == IPHEADER)
	{
		/*
		int partSum = ntohs(CS->part1) + ntohs(CS->part2) + ntohs(CS->part3) + ntohs(CS->part4) + ntohs(CS->part5) + ntohs(CS->part6) + ntohs(CS->part7) + ntohs(CS->part8) + ntohs(CS->part9);
		u_short Bit = partSum >> 16;
		printf("��Ʈ �� : %08x\n", partSum);
		printf("4ĭ �̵� : %08x\n", Bit);
		partSum = partSum - (Bit * 65536);
		printf("�ѱ�� ���� ��Ʈ �� : %04x\n", partSum + Bit);
		printf("���� ���ϱ� : %04x\n", (u_short)~(partSum + Bit));
		printf("üũ�� : %04x\n", ntohs(CS->checksum));
		if (ntohs(CS->checksum) == (u_short)~(partSum + Bit))
			printf("�ջ���� ���� ���� ��Ŷ�Դϴ�.\n");
		else
			printf("�ջ�� ��Ŷ�Դϴ�. �� ���� ��û�� �ؾ� �մϴ�.\n");
		*/
		sprintf(tempBuf,"���� : %d\n", IH->Version);
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		sprintf(tempBuf,"��� ���� : %d\n", (IH->HeaderLength) * 4);
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		sprintf(tempBuf, "���� ���� : %04x\n", IH->TypeOfService);
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		sprintf(tempBuf, "��ü ũ�� : %d\n", ntohs(IH->HeaderLength));//2 bytes �̻� ���ʹ� ������ ������� �ϹǷ� ntohs�Լ��� �Ἥ �����´�.
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		sprintf(tempBuf, "��Ŷ ID : %d\n", ntohs(IH->ID));
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		if (0x4000 == ((ntohs(IH->FlagOffset)) & 0x4000)){
			sprintf(tempBuf, "[1] ����ȭ ���� ���� ��Ŷ�Դϴ�.\n");
			printf("%s", tempBuf);
			fwrite(tempBuf, strlen(tempBuf), 1, fp);
		}
		else{
			sprintf(tempBuf, "[0] ���� ����ȭ�� ��Ŷ\n");
			printf("%s", tempBuf);
			fwrite(tempBuf, strlen(tempBuf), 1, fp);
		}
		if (0x2000 == ((ntohs(IH->FlagOffset)) & 0x2000)){
			sprintf(tempBuf, "[1] ����ȭ�� ��Ŷ�� �� �ֽ��ϴ�.\n");
			printf("%s", tempBuf);
			fwrite(tempBuf, strlen(tempBuf), 1, fp);
		}
		else{
			sprintf(tempBuf, "[0] ������ ��Ŷ�Դϴ�.\n");
			printf("%s", tempBuf);
			fwrite(tempBuf, strlen(tempBuf), 1, fp);
		}
		sprintf(tempBuf, "�����׸�Ʈ ������ : %d[byte]\n", (0x1FFF & ntohs(IH->FlagOffset) * 8));
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		sprintf(tempBuf, "TTL : %d\n", IH->TimeToLive);
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		sprintf(tempBuf, "�������� : %d\n", IH->Protocol);
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		sprintf(tempBuf, "üũ�� : %04x\n", ntohs(IH->checksum));//��) 0x145F
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		sprintf(tempBuf, "��� IP �ּ� : %d.%d.%d.%d\n", IH->SenderAddress.ip1, IH->SenderAddress.ip2, IH->SenderAddress.ip3, IH->SenderAddress.ip4);
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		sprintf(tempBuf, "���� IP �ּ� : %d.%d.%d.%d\n", IH->DestinationAddress.ip1, IH->DestinationAddress.ip2, IH->DestinationAddress.ip3, IH->DestinationAddress.ip4);
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		sprintf(tempBuf, "�ɼ�/�е� : %d\n", IH->Option_Padding);
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);

		sprintf(tempBuf, "�� Protocol : IP\n");
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);
	}
	else if (type == ARPHEADER)
	{
		sprintf(tempBuf, "�� Protocol : ARP\n");
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);
	}
	else if (type == RARPHEADER) {
		sprintf(tempBuf, "�� Protocol : RARP\n");
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);
	}
		sprintf(tempBuf, "����������������������������������������������������\n");
		printf("%s", tempBuf);
		fwrite(tempBuf, strlen(tempBuf), 1, fp);
	
		packetCountNum++;

	/*
	if (packetCountNum == GETPACKETNUMBER) {
		fclose(fp);
	}
	*/
}
