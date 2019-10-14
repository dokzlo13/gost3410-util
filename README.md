# gost3410-util

Util can create and verify signatures by gost341012 with hash function gost341112 "Streebog"


```
ГОСТ 34.10-2018 (полное название: «ГОСТ 34.10-2018. Информационная технология. Криптографическая защита информации. Процессы формирования и проверки электронной цифровой подписи», англ. «Information technology. Cryptographic data security. Signature and verification processes of electronic digital signature») — действующий межгосударственный криптографический стандарт, описывающий алгоритмы формирования и проверки электронной цифровой подписи реализуемой с использованием операций в группе точек эллиптической кривой, определенной над конечным простым полем.

Стандарт разработан на основе национального стандарта Российской Федерации ГОСТ Р 34.10-2012 и введен в действие с 1 июня 2019 года приказом Росстандарта № 1059-ст от 4 декабря 2018 года.
```

```
«Стрибог» — криптографический алгоритм вычисления хеш-функции с размером блока входных данных 512 бит и размером хеш-кода — 256 или 512 бит.

Описывается в ГОСТ 34.11-2018 «Информационная технология. Криптографическая защита информации. Функция хэширования» — действующем межгосударственном криптографическом стандарте.

Разработан Центром защиты информации и специальной связи ФСБ России с участием ОАО «ИнфоТеКС» на основе национального стандарта Российской Федерации ГОСТ Р 34.11-2012 и введен в действие с 1 июня 2019 года приказом Росстандарта № 1060-ст от 4 декабря 2018 года.

Стандарт ГОСТ Р 34.11-2012 разработан и введён в качестве замены устаревшему стандарту ГОСТ Р 34.11-94:
```

## Installation:

1. Download sources

	```bash
	$ git clone https://github.com/dokzlo13/gost3410-util.git
	$ cd gost3410-util
	```
  
2. Install requirements:

	in virtualenv
	
	```bash
	$ virtualenv --python=python3 ./venv 
	$ source ./venv/bin/activate
	[venv]$ pip install -r requirements.txt   
	```
	
	in system interpreter
	
	```bash
	$ sudo pip install -r requirements.txt   
 	```
	
3. Run util

	```bash
	$ python shell.py  
	```

## Info

Util use custom ANS1-structs to store signatures (more info in structs.py).
Signing will create asn1-file [like this](https://lapo.it/asn1js/#MIICljGCAfowggH2DAtnb3N0U2lnbktleQQIODAwNjA3MDAwgYQCQAnucKzKdBbGTR6wsMRISVXWNb1K1gbTmuV6Kz5_bIyLtJVx3AR7Ca539CQFWypWsX8QQqsnMOjNpAj4rI6WS5kCQBBCKrr5sMM0ZHdS8RqIg9seEA7kqlyemZk5NVElQTwYe8elvB_3_l9A4UZ8io9PCc561dAyTwuyJyFqWXI1P7kwQwJBAP___________________________________________________________________________________ccwgYYCQQD___________________________________________________________________________________3EAkEA6MJQXe38ht3BvQsrZmfx2jS4JXR2HLDoeb0IHP0LYmXuPLCQ8w0nYUy0V0AQ2pDdhi751OvuR2FQMZB4WnHHYDBFAgEDAkB1A8_oeoNq46YbiBbiVFDmzl4ck6zxq8F3gGT9y--pId8WJr5P0DbpPXXmpQ46QemAKP5fwjX1uImlictSFfKkAkEA__________________________________________8n5pUy9I2JEW_yK41OBWBgm0s4q_rSuF3KzbFBHxCydTCBhQJBAN853HTlcfNghN3RxOnwUEJnvY2vLYy_jsWQzXbxMp_FTWhE_pbmEnwxgZki3d4mtyKoJ4RBajxfuK5vUuYn_WMCQAuYcEjkCi4bRsQGjObLR-0FzRFPOdVm3ZBDDF15m6LL0W7ZYvOQ4pPmZdjb8mIxn1J2qsI27fvgtXWV6cB6hTcwDgICDo0MCGRhdGEudHh0)

Thanks Sergey Matveev <stargrave@stargrave.org> for [pygost](http://pygost.cypherpunks.ru/Download.html#Download) and [sources](https://git.cypherpunks.ru/cgit.cgi/pygost.git/). Old version also available at [github](https://github.com/ilyaTT/pygost_0_15).

## Usage example

```
[venv]gost3410 » python shell.py                                                      
Welcome to GOST 34.10-2012 signature util v0.0.1 shell. Type help or ? to list commands.

[] ~# help

Documented commands (type help <topic>):
========================================
clear  delkey  exit  genkeys  help  keylist  sign  use  verify

[] ~# genkeys
 Please, select Curve params:

 1: GostR3410_2012_TC26_ParamSetA
         p FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF...FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7
         q FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF...116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275
         a FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF...FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4
         b E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879...614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760
         x 00000000000000000000000000000000000000000000000000...00000000000000000000000000000000000000000000000003
         y 7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC177...E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4

 2: GostR3410_2012_TC26_ParamSetB
         p 80000000000000000000000000000000000000000000000000...0000000000000000000000000000000000000000000000006F
         q 80000000000000000000000000000000000000000000000000...45ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD
         a 80000000000000000000000000000000000000000000000000...0000000000000000000000000000000000000000000000006C
         b 687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF...217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116
         x 00000000000000000000000000000000000000000000000000...00000000000000000000000000000000000000000000000002
         y 1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE...39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD

Select parameters index: 1

You choose curve param set "GostR3410_2012_TC26_ParamSetA"

Keys generated!

================== Keypair     1 ========================
Public Key:
        X: 50880086009957338442907311345913844646572829736569...36607729858543008180429123643076047879601057859037 (511 bits)
        Y: 37883472096345974397350964327080176716922297428749...56356222998073446088852048222536383709185858784061 (511 bits)
Private Key:
        12697703492663906191285431136216130998170344135654...68860518060595846276714728649073054335611395288255 (1024 bits)
Curve:
        p: 13407807929942597099574024998205846127479365820592...31858186486050853753882811946569946433649006083527 (512 bits)
        q: 13407807929942597099574024998205846127479365820592...28612556596899500625279906416653993875474742293109 (512 bits)
        a: 13407807929942597099574024998205846127479365820592...31858186486050853753882811946569946433649006083524 (512 bits)
        b: 12190580024266230156189424758340094075514844064736...39088997221609947354520590448683948135300824418144 (512 bits)
        x: 3 (2 bits)
        y: 61285671321593683755506766505341533718267088079063...05107369028606191097747738367571924466694236795556 (511 bits)


[] ~# use 1
[keys(1)] ~# sign ./testdata/lorem.txt
Message hash: b'80302fc206780fe7fd6a2d6bec2744308f10341aad76bab973c62cc182aeccd3'

Generated ASN.1 file:

SignatureSequence:
 params=KeyDataSet:
  keydatasquence=KeyDataSequence:
   text=gostSignKey
   algo=80060700
   open_key=OpenKey:
    x=50880086009957338442907311345913844646572829736569...36607729858543008180429123643076047879601057859037
    y=37883472096345974397350964327080176716922297428749...56356222998073446088852048222536383709185858784061

   cryptosystem_p=CryptosystemParams:
    p=13407807929942597099574024998205846127479365820592...31858186486050853753882811946569946433649006083527

   curve_p=CurveParams:
    a=13407807929942597099574024998205846127479365820592...31858186486050853753882811946569946433649006083524
    b=12190580024266230156189424758340094075514844064736...39088997221609947354520590448683948135300824418144

   dots_p=DotsParams:
    x=3
    y=61285671321593683755506766505341533718267088079063...05107369028606191097747738367571924466694236795556

   q=13407807929942597099574024998205846127479365820592...28612556596899500625279906416653993875474742293109


 sign=SignatureParamsSequence:
  r=10632034449140550935353013381040865146612482367283...68326234363786350314636826757595654398001324470644
  s=12347966916203096551728780732924422280679145810019...80681041905788269690425303934046509439197121170213

 meta=FileMetaSequence:
  filesize=3724
  filename=lorem.txt



Signature created!

[keys(1)] ~# verify ./testdata/lorem.txt ./testdata/lorem.txt.sign

Read ASN.1 file:

SignatureSequence:
 params=KeyDataSet:
  keydatasquence=KeyDataSequence:
   text=gostSignKey
   algo=80060700
   open_key=OpenKey:
    x=50880086009957338442907311345913844646572829736569...36607729858543008180429123643076047879601057859037
    y=37883472096345974397350964327080176716922297428749...56356222998073446088852048222536383709185858784061

   cryptosystem_p=CryptosystemParams:
    p=13407807929942597099574024998205846127479365820592...31858186486050853753882811946569946433649006083527

   curve_p=CurveParams:
    a=13407807929942597099574024998205846127479365820592...31858186486050853753882811946569946433649006083524
    b=12190580024266230156189424758340094075514844064736...39088997221609947354520590448683948135300824418144

   dots_p=DotsParams:
    x=3
    y=61285671321593683755506766505341533718267088079063...05107369028606191097747738367571924466694236795556

   q=13407807929942597099574024998205846127479365820592...28612556596899500625279906416653993875474742293109


 sign=SignatureParamsSequence:
  r=10632034449140550935353013381040865146612482367283...68326234363786350314636826757595654398001324470644
  s=12347966916203096551728780732924422280679145810019...80681041905788269690425303934046509439197121170213

 meta=FileMetaSequence:
  filesize=3724
  filename=lorem.txt



Signature checking successful!

[keys(1)] ~# exit
[venv]gost3410 »    
```