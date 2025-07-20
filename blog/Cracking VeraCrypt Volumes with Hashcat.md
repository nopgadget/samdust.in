# Cracking VeraCrypt Volumes with Hashcat

*July 19, 2023*

In creating a Capture-The-Flag competition for my College Cybersecurity group, I have streamlined and documented the process for cracking Veracrypt Volumes.

## Background

Veracrypt is the successor of TrueCrypt, after its final release in 2014. Veracrypt has slowly gained popularity among users, and notoriety in the Digital Forensics community.

(For relevant examples of legal cases surrounding True/VeraCrypt, view [https://en.wikipedia.org/wiki/TrueCrypt#Legal_cases](https://en.wikipedia.org/wiki/TrueCrypt#Legal_cases))

Grossing nearly 10,000 downloads/month at the time of writing, VeraCrypt is a massive provider of data encryption for individuals and corporations.

![VeraCrypt Volume Structure](img/blog/veracrypt-volume-structure.png)
*VeraCrypt volume structure showing standard and hidden volume headers*

## Cracking Veracrypt Volumes - The Process

Before diving into the technical aspects of Veracrypt Volume cracking, it's essential to comprehend the structure of a Veracrypt Volume and the critical steps involved in the decryption process.

## Veracrypt Volume Structure

![VeraCrypt Volume Structure](img/blog/veracrypt-volume-structure.png)

*From https://www.veracrypt.fr/en/Hidden%20Volume.html*

Veracrypt first attempts to decrypt the standard volume header using the provided password. If this attempt fails, it then accesses a specific area of the volume that could potentially contain a hidden volume header (bytes 65536–131071). When there is no hidden volume within the volume, these bytes hold random data.

[https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)

[https://github.com/hashcat/hashcat/blob/master/tools/truecrypt2hashcat.py](https://github.com/hashcat/hashcat/blob/master/tools/truecrypt2hashcat.py)

## Decrypting the Volume

To proceed with the decryption, bytes 65536–66047 of the volume are read into RAM. For system encryption, the bytes from the first partition located behind the active partition are read (see the section Hidden Operating System). If there exists a hidden volume within this volume or the partition behind the boot partition, the header is read at this point. Otherwise, it reads random data, and the presence of a hidden volume needs to be determined by attempting to decrypt this data.

![VeraCrypt Decryption Process](img/blog/veracrypt-decryption.png)
*VeraCrypt decryption process showing byte reading and header verification*

## Successful Decryption

A successful decryption of Veracrypt Volume is indicated by the first 4 bytes of the decrypted data containing the ASCII string 'VERA' ([https://www.veracrypt.fr/en/Encryption%20Scheme.html](https://www.veracrypt.fr/en/Encryption%20Scheme.html)). This verification ensures that the correct password has been used and the volume has been decrypted successfully.

![Successful Decryption](img/blog/veracrypt-successful-decryption.png)

## Extracting Hashes from TrueCrypt Volumes

To extract the hashes from TrueCrypt volumes (which are also applicable to Veracrypt), the [frequently asked questions](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_do_i_extract_the_hashes_from_truecrypt_volumes) on Hashcat's website contains a score of relevant and useful information.

![Hash Extraction](img/blog/hashcat-hash-extraction.png)

## Utilizing Hashcat for Cracking

Hashcat is a powerful password cracking tool capable of tackling various encryption schemes, now including Veracrypt.

Extraction is possible utilizing now available hash cracking methods, and the truecrypt2hashcat.py script available on the Hashcat GitHub repository, extracting the password from VeraCrypt containers is made possible using the [module_29421.c](https://github.com/hashcat/hashcat/blob/master/src/modules/module_29421.c) module (cracking mode 29421) provided in the Hashcat GitHub repository.

These modules were developed in June 7 2022 by a polish developer. Before this, TrueCrypt / VeraCrypt cracking methods were not streamlined or available to the public. Utilizing the "VERA" principle, the developer made the cracking process much faster. Now that these are available, investigators have another tool in their arsenal to be able to further their forensic evidence.

![Hashcat Cracking](img/blog/hashcat-cracking-process.png)

---

*This guide is for educational purposes only. Always ensure you have proper authorization before attempting to crack any encrypted volumes.* 