### **Assignment 2 Report**  
#### CSCI/CSCY 4743: Cyber and Infrastructure Defense, Spring 2025  

**Name & Student ID**: [Allen Lu], [109385233]  

**Please select your course number:**  
- [x] CSCI 4743  
- [ ] CSCY 4743  

---

# **Section 1: Conceptual Assignments**  

### **1. ARP Poisoning & Advanced MITM Techniques**  
**Overview of ARP Poisoning**
ARP poisoning, also known as ARP spoofing, is a network attack where an attacker sends falsified ARP messages to manipulate the ARP cache of devices within a local network. ARP (Address Resolution Protocol) maps IP addresses to MAC addresses, enabling communication between devices. By associating their MAC address with the IP of a legitimate device (e.g., a router), the attacker can intercept, modify, or disrupt traffic.

**Attack Execution**
In a typical ARP poisoning attack, tools like arpspoof or Bettercap are used to send malicious ARP packets. This misleads devices into sending traffic to the attacker instead of the intended destination. For example, if the attacker poisons the ARP table to associate their MAC address with the gateway IP, all outgoing traffic flows through the attacker’s machine. They can capture sensitive information, such as passwords, session tokens, or inject malicious content into legitimate web pages. Advanced attacks may combine ARP poisoning with DNS spoofing or SSL stripping, further compromising security by downgrading HTTPS to HTTP, exposing users to eavesdropping.

**Countermeasures**
Several strategies can mitigate ARP poisoning attacks:
- **Dynamic ARP Inspection (DAI):** This feature on managed switches validates ARP packets, ensuring they are legitimate and preventing malicious ARP replies from being processed.
- **HTTPS and TLS Encryption:** Using HTTPS with TLS and certificate pinning ensures that sensitive data remains encrypted, even if traffic is intercepted.
- **Network Monitoring:** Tools like Wireshark or Snort can identify suspicious ARP traffic, enabling early detection of ARP poisoning.
- **Endpoint Protection:** Software that monitors and blocks suspicious ARP traffic can prevent unauthorized changes to the ARP cache.

**Real-World Example**
In 2014, a group of hackers targeted a corporate network using ARP poisoning to intercept internal communications, capturing sensitive data such as login credentials and private messages. The attack highlighted the critical need for securing network traffic and implementing proactive defenses.


### **2. ARP Spoofing in IPv6 Networks**  
**Introduction to NDP and ARP Spoofing in IPv6**
In IPv6 networks, ARP is replaced by the Neighbor Discovery Protocol (NDP), which handles address resolution, router discovery, and network prefix detection. While NDP improves on ARP, it is also vulnerable to spoofing attacks, where attackers send malicious Neighbor Advertisement (NA) messages to associate their MAC address with a victim's IPv6 address.

**Attack Execution**
In an NDP spoofing attack, the attacker broadcasts false NA messages, misleading devices into updating their neighbor cache with incorrect mappings. This creates opportunities for Man-in-the-Middle (MITM) attacks, where the attacker intercepts and modifies traffic. Alternatively, attackers can launch Denial of Service (DoS) attacks by causing devices to send packets to non-existent endpoints. Rogue Router Advertisement (RA) attacks further exploit NDP vulnerabilities by tricking devices into using a malicious gateway.

**Mitigation Strategies**
- **Secure Neighbor Discovery (SEND):** SEND adds cryptographic protections to NDP messages, making it difficult for attackers to forge NA and RA messages.
- **RA Guard and DHCPv6 Guard:** These features on routers and switches filter out malicious RAs and rogue DHCPv6 servers, preventing unauthorized devices from hijacking the network.
- **Intrusion Detection Systems (IDS):** IPv6-aware IDS can detect unusual NDP traffic patterns and help identify spoofing attempts early.

**Real-World Example**
In a university network, attackers exploited NDP vulnerabilities to redirect traffic through their machine, intercepting sensitive academic records. This highlighted the importance of securing NDP to prevent unauthorized traffic redirection and data breaches.


### **3. DHCP Starvation & Rogue DHCP for Long-Term Persistence**  
**Overview of DHCP Starvation**
DHCP starvation is an attack in which an attacker floods the DHCP server with numerous requests, each using a different MAC address. This quickly exhausts the server’s IP address pool, preventing legitimate devices from obtaining network access. Attackers often follow up by setting up a rogue DHCP server that assigns malicious configurations, allowing them to control network traffic.

**Attack Execution**
Once the attacker exhausts the DHCP pool, they deploy a rogue DHCP server to assign IP addresses, DNS settings, and gateways that route traffic through the attacker's system. This creates opportunities for MITM attacks, data interception, or even DNS spoofing. Tools like Yersinia automate the process, making it easy for attackers to execute the attack on large networks.

**Mitigation Strategies**
- **DHCP Snooping:** This feature on managed switches filters untrusted DHCP messages, ensuring that only legitimate servers can assign IP addresses.
- **Rate Limiting:** Limiting the number of DHCP requests from a single device can mitigate the impact of starvation attacks.
- **Network Access Control (NAC):** NAC solutions ensure that only authorized devices can join the network, reducing the attack surface for rogue DHCP servers.

**Real-World Example**
In 2016, a large organization suffered a data breach after attackers conducted a DHCP starvation attack and deployed a rogue DHCP server. The attackers were able to redirect traffic through their server, stealing sensitive information before the attack was detected.


### **4. VLAN Hopping & Subverting Network Segmentation**  
**Introduction to VLAN Hopping**
VLAN hopping occurs when an attacker gains unauthorized access to different network segments by exploiting weaknesses in VLAN configurations. VLANs are designed to segregate network traffic for security and performance, but flaws in the setup can allow attackers to bypass these segments and access restricted areas.

**Attack Execution**
There are two primary VLAN hopping techniques:
- **Switch Spoofing:** The attacker configures their device to impersonate a switch, tricking a legitimate switch into sending them traffic from multiple VLANs.
- **Double Tagging:** The attacker inserts two VLAN tags into a frame. The first switch strips the first tag, and the second switch forwards the packet to another VLAN, bypassing security restrictions.

**Mitigation Strategies**
- **Disable Dynamic Trunking Protocol (DTP):** Preventing DTP on non-trunking ports stops attackers from impersonating switches.
- **Access Control Lists (ACLs):** ACLs can restrict traffic between VLANs, preventing unauthorized access.
- **Private VLANs:** These create isolated environments within a VLAN, limiting access between devices within the same segment.

**Real-World Example**
In 2018, an attacker exploited a misconfigured VLAN in a corporate network, gaining access to a segment with sensitive financial data. The attack was possible because the VLAN was improperly configured, allowing the attacker to bypass network segmentation controls.


### **5. Wireless Attacks: Rogue AP vs. Evil Twin**  
**Overview of Wireless Attacks**
Wireless networks are inherently vulnerable to various attacks due to their broadcast nature. Rogue Access Points (APs) and Evil Twin attacks are two common threats that compromise wireless security.

**Rogue AP vs. Evil Twin**
- **Rogue AP:** An unauthorized AP is connected to the network, either maliciously or by user mistake. This device can intercept traffic, steal credentials, or create backdoors for attackers.
- **Evil Twin:** An attacker sets up a fake AP with the same SSID as a legitimate network, tricking users into connecting. Once connected, attackers can intercept communications and capture sensitive data.

**Mitigation Strategies**
- **Wireless Intrusion Detection Systems (WIDS):** These systems detect rogue APs and unusual wireless activity, providing early warning of potential threats.
- **WPA3 Encryption:** Enforcing WPA3 with certificate-based authentication prevents unauthorized devices from connecting to the network.
- **User Awareness:** Users should verify the SSID before connecting to ensure they are not connecting to an Evil Twin. Encouraging VPN usage adds an additional layer of protection.

**Real-World Example**
In 2015, hackers used an Evil Twin attack at a coffee shop, capturing the personal data of several users who unknowingly connected to the fake network. This attack demonstrated the importance of verifying wireless connections and using encrypted communications.

### **6. IP Spoofing in Multi-Stage Attacks**  
**Introduction to IP Spoofing**  
IP spoofing is a technique where an attacker forges the source IP address in network packets to disguise their identity or impersonate another system. While often used in Denial-of-Service (DoS) attacks, IP spoofing is also a critical component of multi-stage attacks, enabling persistence, evasion, and lateral movement.

**Attack Execution**  
One common use of IP spoofing in multi-stage attacks is in reconnaissance. Attackers forge IP addresses to evade intrusion detection systems (IDS) while scanning for vulnerabilities. By making requests appear as if they originate from legitimate sources, attackers can gather intelligence on potential targets without triggering security alerts.

Another scenario is session hijacking, where an attacker spoofs a trusted IP address to intercept or inject packets into an active session. In corporate networks, an attacker might spoof an administrator's IP to gain unauthorized access to internal systems. This technique is particularly dangerous when combined with credential theft or man-in-the-middle attacks.

**Mitigation Strategies**  
- **Ingress and Egress Filtering:** Implementing filtering on routers helps block packets with forged IP addresses.  
- **Network Anomaly Detection:** Identifying suspicious patterns in traffic can alert network administrators to potential spoofing attempts.  
- **Authentication Mechanisms:** TLS and mutual authentication help prevent session hijacking by ensuring the legitimacy of communication endpoints.  
- **Firewalls and Logging:** Employing strict firewall rules and detailed logging can help track unexpected source IP activity, reducing the effectiveness of spoofing techniques.

**Real-World Example**  
IP spoofing is frequently used in advanced persistent threat (APT) campaigns, where attackers forge IP addresses to maintain stealth and infiltrate corporate networks. One such attack involved spoofing a trusted IP to hijack an active session, gaining access to sensitive internal data without raising alarms.


### **7. DNS Cache Poisoning: Evolution of Attacks**  
**Overview of DNS Cache Poisoning**  
DNS cache poisoning, also known as DNS spoofing, is an attack where malicious entries are inserted into the DNS cache of a resolver, causing users to be redirected to fraudulent sites. This attack exploits vulnerabilities in the DNS system, which translates domain names into IP addresses. By corrupting DNS records, attackers can impersonate legitimate websites, intercept sensitive data, and spread malware.

**Attack Execution**  
Early DNS cache poisoning attacks relied on the predictability of DNS query IDs. Attackers would flood a DNS resolver with fake responses, hoping to match the correct ID and overwrite the legitimate record. Over time, attackers developed more sophisticated techniques, such as exploiting vulnerabilities in DNS software or leveraging man-in-the-middle (MITM) tactics to inject malicious DNS responses directly.

A notable example is the 2008 Kaminsky attack, which revealed that attackers could poison DNS caches by exploiting transaction ID predictability and UDP’s lack of authentication. This attack could redirect entire domains, making phishing campaigns highly effective.

**Mitigation Strategies**  
- **DNSSEC:** Domain Name System Security Extensions (DNSSEC) add cryptographic signatures to DNS records, ensuring data integrity and authenticity.  
- **Randomized Query IDs:** Randomizing source ports and query IDs makes it harder for attackers to guess the correct response parameters.  
- **Encrypted DNS:** Using DNS over HTTPS (DoH) or DNS over TLS (DoT) prevents tampering with DNS queries.  
- **Regular Updates:** Keeping DNS software updated and patched ensures known vulnerabilities are mitigated.

**Real-World Example**  
In 2008, the Kaminsky attack exposed vulnerabilities in the DNS system, allowing attackers to poison caches and redirect users to fake websites. This event spurred the widespread adoption of DNSSEC and highlighted the need for enhanced security in the DNS infrastructure.

### **8. BGP Hijacking: Attackers as Network Operators**  
**Overview of BGP Hijacking**  
Border Gateway Protocol (BGP) hijacking is a severe attack where malicious actors manipulate BGP routing tables to redirect or intercept internet traffic. BGP is the protocol that governs how routers communicate and exchange routing information between autonomous systems (AS). Because BGP relies heavily on trust, attackers can exploit its lack of built-in authentication to falsely announce IP prefixes, effectively rerouting traffic through malicious networks.

**Attack Execution**  
In a typical BGP hijacking scenario, attackers announce IP ranges they don’t own, causing nearby routers to update their routing tables and send traffic through the attacker’s infrastructure. This allows attackers to eavesdrop on communications, perform man-in-the-middle (MITM) attacks, or disrupt services by blackholing traffic. Notable incidents include the 2008 YouTube outage, where a Pakistani ISP accidentally hijacked YouTube’s IP prefixes, and more targeted attacks against cryptocurrency platforms and financial institutions.

**Mitigation Strategies**  
- **RPKI:** Resource Public Key Infrastructure (RPKI) helps authenticate route announcements, verifying that the originating AS is authorized to advertise specific IP prefixes.  
- **Route Filtering:** Implementing route filtering and monitoring with tools like BGPmon or RIPE Atlas can detect suspicious route changes.  
- **MANRS Best Practices:** Adopting the Mutually Agreed Norms for Routing Security (MANRS) practices encourages ISPs to enhance their routing security.

**Real-World Example**  
In 2008, YouTube experienced a widespread outage when a Pakistani ISP inadvertently hijacked YouTube's IP prefixes, redirecting traffic and disrupting services. This incident demonstrated the critical need for better BGP security to prevent malicious rerouting.



### **9. Amplification DDoS Attacks: DNS vs. NTP vs. Memcached**  
**Overview of Amplification DDoS Attacks**  
Amplification DDoS attacks exploit vulnerable protocols to magnify the volume of malicious traffic sent to a target, overwhelming systems and causing service disruptions. Attackers use spoofed IP addresses to send small requests that generate massive responses, directing the amplified traffic at their victim.

**Attack Execution**  
- **DNS Amplification:** Attackers exploit open DNS resolvers to flood targets with large DNS responses by sending small queries with a spoofed source IP (the victim’s address), triggering responses many times larger.  
- **NTP Amplification:** Abusing the monlist command in NTP servers, attackers can drastically increase response sizes, amplifying traffic aimed at the victim.  
- **Memcached Amplification:** Memcached amplification is even more potent, with amplification factors of up to 51,000x, achieved by sending small UDP packets to vulnerable Memcached servers, creating massive traffic floods.

**Mitigation Strategies**  
- **Rate Limiting:** Limiting the rate of requests from a single device helps mitigate the impact of amplification attacks.  
- **Disabling Unnecessary UDP Services:** Disabling services like monlist in NTP can reduce opportunities for abuse.  
- **Ingress Filtering:** Using BCP38 filtering can block spoofed packets, preventing attackers from amplifying traffic.  
- **DDoS Protection Services:** Web application firewalls (WAFs) and services like Cloudflare or AWS Shield can absorb and mitigate DDoS attack traffic.

**Real-World Example**  
In 2018, a Memcached amplification attack caused one of the largest DDoS attacks recorded at the time, with an amplification factor of over 51,000x. The attack overwhelmed networks, demonstrating the danger of unsecured UDP services and the need for better DDoS defenses.


### **10. DDoS Mitigation: Proactive vs. Reactive Defense**  
**Overview of DDoS Mitigation**  
DDoS mitigation involves both proactive and reactive strategies to protect against the impact of Distributed Denial-of-Service (DDoS) attacks. Proactive defense focuses on preparing systems to withstand attacks, while reactive defense focuses on responding effectively when an attack occurs.

**Proactive Defense**  
Proactive DDoS defense includes:  
- **Traffic Filtering:** Deploying filtering solutions to block malicious traffic before it reaches the target.  
- **Rate Limits:** Configuring rate limits to reduce the volume of traffic hitting the server.  
- **Scrubbing Services:** Using services that analyze traffic and drop malicious requests before they affect the infrastructure.  
- **Network Stress Tests:** Regularly testing the network for vulnerabilities and preparing for potential attack scenarios.

**Reactive Defense**  
Reactive defense involves:  
- **Incident Response Teams:** Quickly identifying attack vectors and deploying teams to mitigate the damage.  
- **Traffic Rerouting:** Redirecting traffic through scrubbing centers to mitigate the impact of an ongoing attack.  
- **Recovery Plans:** Having a plan in place to restore services quickly after an attack.

**Best Strategy**  
The best DDoS mitigation strategy blends proactive and reactive defenses, combining preemptive measures with the agility to respond to attacks effectively. This hybrid approach ensures resilience against even the most sophisticated DDoS campaigns.

**Real-World Example**  
In 2016, the Dyn DDoS attack disrupted major websites across the globe, showing how unprepared systems can be overwhelmed. The response involved rerouting traffic through scrubbing centers and deploying DDoS mitigation tools to restore services.

### **11. Emerging Cyber Threats in Cloud & AI-Driven Networks**  
**Overview of Emerging Threats**  
As organizations increasingly migrate to cloud environments and adopt AI-driven networks, they face a new wave of cyber threats. The cloud is inherently vulnerable due to its internet accessibility, enabling attackers to exploit misconfigurations, insufficient access controls, and shared infrastructure vulnerabilities. Threats such as account hijacking, data breaches, and ransomware attacks are exacerbated by the vast amounts of data and services hosted in cloud environments.

AI-driven networks, while improving efficiency and security through automated threat detection, are also subject to risks. Adversarial attacks can manipulate AI models, feeding deceptive inputs to cause misclassification or bypass defenses. Additionally, attackers can exploit AI systems to refine their tactics, conducting automated reconnaissance and launching more sophisticated phishing campaigns.

**Attack Execution**  
In AI-driven environments, adversarial attacks often involve feeding adversarial inputs that can mislead machine learning models into making incorrect predictions or classifications. Attackers may also craft sophisticated attack patterns by exploiting AI’s automated processes, enabling them to bypass traditional defenses.

**Mitigation Strategies**  
- **Identity & Access Management (IAM):** Strong IAM policies ensure that only authorized users have access to critical resources.  
- **Continuous Monitoring:** Real-time monitoring for anomalies helps detect abnormal behavior and potential attacks.  
- **Data Encryption:** Encrypting sensitive data both in transit and at rest adds an additional layer of protection.  
- **Security Audits:** Regular security audits and penetration testing help identify vulnerabilities and mitigate risks before they are exploited.

**Real-World Example**  
In 2020, attackers targeted cloud-hosted databases, exploiting misconfigured cloud storage to gain unauthorized access to sensitive data. The incident highlighted the need for robust cloud security practices, including proper configuration management, encryption, and real-time monitoring.


### **12. Shaping Your Security Mindset**  
**Overview of Security Mindset**  
Fostering a security-first mindset within an organization is vital in defending against today’s cyber threats. This involves embedding security awareness at every level, ensuring that cybersecurity is a shared responsibility across all teams, not just the IT department. Employees should be trained to identify phishing attempts, practice good password hygiene, and report suspicious activities promptly.

**Security Execution**  
Security efforts should involve regular training and awareness programs to help employees recognize various types of threats, such as social engineering and phishing. On a broader scale, organizations should adopt a **risk-based security approach**, focusing on areas most likely to be targeted based on threat intelligence and potential impact.

**Mitigation Strategies**  
- **Phishing Awareness Training:** Training employees to recognize phishing emails and suspicious links helps reduce the risk of credential theft.  
- **Risk-Based Security Strategy:** Prioritizing security investments based on the most likely and impactful threats ensures effective resource allocation.  
- **Regular Penetration Testing:** Simulating attacks helps identify weaknesses in the organization’s defenses and provides opportunities to improve.

**Real-World Example**  
In 2017, the **WannaCry ransomware attack** demonstrated the importance of a security-first mindset. The attack exploited unpatched Windows systems, which could have been mitigated with better awareness and quicker patch management.


### **13. Designing a Secure Network: VLAN Segmentation & Access Control**  
**Overview of VLAN Segmentation & Access Control**  
A secure network is built upon effective design, and VLAN segmentation combined with robust access control mechanisms serves as a critical security measure. **VLANs** (Virtual Local Area Networks) divide a network into isolated segments, reducing the attack surface by limiting broadcast domains and preventing lateral movement within the network.  

**Attack Execution**  
Without proper segmentation, attackers can move freely across a network once they compromise a single device. VLANs restrict this movement, making it harder for attackers to escalate privileges or access sensitive resources. Additionally, access control measures such as **role-based access control (RBAC)** ensure that only authorized users and devices can access specific resources.

**Mitigation Strategies**  
- **VLAN Segmentation:** Properly configured VLANs can isolate sensitive data, minimizing exposure to potential threats.  
- **Network Access Control (NAC):** NAC solutions ensure that only authorized devices are allowed to connect to the network.  
- **Multi-Factor Authentication (MFA):** Requiring multiple forms of verification for accessing critical systems strengthens access controls.

**Real-World Example**  
In 2016, the **Mirai Botnet** used IoT devices to perform large-scale DDoS attacks. By segmenting networks and implementing stricter access controls, such attacks could have been contained within a smaller portion of the network, reducing the impact on critical systems.


### **14. Protecting Against DDoS & Global Threats**  
**Overview of DDoS Attacks & Global Threats**  
**DDoS (Distributed Denial of Service)** attacks continue to be one of the most effective methods for attackers to disrupt services and cause financial losses. These attacks flood a target with traffic, overwhelming its resources and making it unavailable to legitimate users. Global threats, including state-sponsored attacks and supply chain compromises, also pose significant risks, requiring continuous vigilance and sophisticated defense strategies.

**Attack Execution**  
In a DDoS attack, the attacker uses a network of compromised devices (often referred to as a botnet) to flood a target with an overwhelming amount of traffic. This can render online services and websites inoperable for extended periods, disrupting businesses and operations. In the case of state-sponsored attacks, the intent is often more strategic, with attackers targeting critical infrastructure or attempting to destabilize a nation's economy.

**Mitigation Strategies**  
- **Traffic Filtering & Rate Limiting:** Deploying traffic filtering and rate limiting solutions can help mitigate the impact of DDoS attacks by blocking malicious traffic before it reaches critical systems.  
- **Cloud-Based DDoS Protection:** Using services such as **Cloudflare** or **AWS Shield** helps absorb large-scale attacks and maintain service availability.  
- **Incident Response Protocols:** Establishing predefined response protocols ensures that organizations can act quickly and efficiently during an attack.

**Real-World Example**  
In 2016, **Dyn**, a provider of domain name services, was attacked by a massive DDoS botnet powered by IoT devices. The attack brought down major websites like Twitter, Netflix, and Reddit. This incident underscored the importance of robust DDoS defenses and proactive monitoring.


### **15. LAN Security: Preventing Internal Threats & Lateral Movement**  
**Overview of LAN Security & Internal Threats**  
**LAN (Local Area Network)** security is vital for protecting internal systems from both external and internal threats. While external attacks are often the primary focus, insider threats — either from malicious actors or compromised devices — can be just as damaging. Preventing **lateral movement**, where attackers traverse a network to access valuable assets, requires comprehensive security measures.

**Attack Execution**  
Attackers who gain access to a LAN can move laterally, using unsegmented networks and weak access controls to access and exploit sensitive data. This type of attack often involves escalating privileges and pivoting from compromised systems to other targets within the network.

**Mitigation Strategies**  
- **Network Segmentation:** Implementing VLANs and firewalls limits lateral movement, ensuring that a compromised device cannot easily access other parts of the network.  
- **Endpoint Detection & Response (EDR):** EDR solutions provide visibility into endpoint activity, allowing organizations to detect suspicious behavior and quickly isolate threats.  
- **User Activity Monitoring:** Monitoring user behavior using **behavioral analytics** helps detect anomalies that could indicate insider threats.

**Real-World Example**  
In 2017, the **Equifax breach** exposed the personal information of 147 million people. The breach was due to both an unpatched vulnerability and internal flaws in network segmentation, which allowed attackers to move laterally within the company’s network and access sensitive data.
---

# **Section 2: Hands-on Network Attacks**  

---

## **Attack 1: ARP Spoofing (Local MITM – Simplified Version)**  

### **Deliverables**  

#### **Screenshots**  

#### **Response to Analysis Questions**    

*(150-300 words response here)* 

---

## **Attack 2: SYN Flood (With and Without IP Spoofing)**  

### **Deliverables**  

#### **Screenshots**  

#### **Response to Analysis Questions**     

*(150-300 words response here)* 

---

## **Attack 3: Exploiting a Vulnerable Service (Remote Code Execution – RCE)**  

### **Deliverables**  

#### **Screenshots**  

#### **Response to Analysis Questions**

*(150-300 words response here)* 

---

## **Attack 4: Passive LAN Sniffing & Reconnaissance with Wireshark**  

### **Deliverables**  

#### **Screenshots**  

#### **Response to Analysis Questions**   

*(150-300 words response here)* 


---

