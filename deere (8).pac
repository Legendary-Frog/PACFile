// JOHN DEERE SPECIFIC
function FindProxyForURL(url, host) {
var lhost = host.toLowerCase();
host = lhost;
var resolved_ip = dnsResolve(host);
var country = "United States";
if (isPlainHostName(host) ||
		shExpMatch(host, "*.local") ||
		shExpMatch(host, "localhost") ||
		isInNet(resolved_ip, "0.0.0.0", "255.255.255.255") ||
		isInNet(resolved_ip, "10.0.0.0", "255.0.0.0") ||
		isInNet(resolved_ip, "169.254.0.0",  "255.255.0.0") ||
		isInNet(resolved_ip, "172.16.0.0",  "255.240.0.0") ||
		isInNet(resolved_ip, "192.168.0.0",  "255.255.0.0") ||
		isInNet(resolved_ip, "192.40.52.18", "255.255.255.255") ||
		isInNet(resolved_ip, "127.0.0.0", "255.0.0.0") ||
	//sctask
		isInNet(resolved_ip, "64.37.104.146", "255.255.255.255") ||
	// Teams subnets		
		isInNet(resolved_ip, "52.112.0.0", "255.252.0.0") ||
		isInNet(resolved_ip, "52.120.0.0", "255.252.0.0") ||
		isInNet(resolved_ip, "13.107.64.0", "255.255.192.0") ||
	// end Teams subnets
		isInNet(resolved_ip, "100.64.0.0","255.255.0.0"))
		return "DIRECT";

    /*
    Send everything other than HTTP and HTTPS direct.
    Uncomment the middle line if FTP over HTTP is enabled in portal.
    */
    if ((url.substring(0,5) != "http:") &&
//    (url.substring(0,4) != "ftp:") &&
    (url.substring(0,6) != "https:"))

	return "DIRECT";


    // Most special use IPv4 addresses (RFC 5735) defined within this regex.
    var privateIP = /^(0|10|127|192.168|172.1[6789]|172.2[0-9]|172.3[01]|169.254|192.88.99)\.[0-9.]+$/;
    // If host is specified as IP address, and it is private, send direct.
    if (privateIP.test(host))

	return "DIRECT";

    // Special Bypasses for SAML, VPN, and Exchange
    if (shExpMatch(host, "*.okta.com") ||
		shExpMatch(host, "*localhost") ||
		shExpMatch(host, "*.oktacdn.com") ||
		shExpMatch(host, "*.oktapreview.com") ||
		shExpMatch(host, "johndeerequal.kerberos.oktapreview.com") ||
		shExpMatch(host, "johndeere.kerberos.okta.com") ||
		shExpMatch(host, "sso.johndeere.com") ||
		shExpMatch(host, "sso-qual.johndeere.com") ||
		shExpMatch(host, "sso-dev.johndeere.com") ||
		shExpMatch(host, "sso-cert.johndeere.com") ||
		shExpMatch(host, "*jdvpn.deere.com") ||
		shExpMatch(host, "*jdvpn-s.deere.com") ||
		shExpMatch(host, "*labvpn-s.deere.com") ||
		shExpMatch(host, "*vpnlab.deere.com") ||
		shExpMatch(host, "*.prod.zpath.net") ||
		shExpMatch(host, "*.private.zscaler.com") ||
		shExpMatch(host, "*.zpa-auth.net") ||
		shExpMatch(host, "*.zpa-app.net") ||
		shExpMatch(host, "*.okta-emea.com") ||
		shExpMatch(host, "*.jdisonsite.com") ||
		shExpMatch(host, "*vpn.starfirenetwork.com") ||
		shExpMatch(host, "*vpn-lax.starfirenetwork.com") ||
		shExpMatch(host, "*vpn-lax-bu.starfirenetwork.com") ||
		shExpMatch(host, "vpn-mli.starfirenetwork.com") ||
		shExpMatch(host, "*vpn.nortrax.com") ||
		shExpMatch(host, "*vpntest.nortrax.com") ||
		shExpMatch(host, "teams.microsoft.com") ||
		shExpMatch(host, "*.teams.microsoft.com") ||
		shExpMatch(host, "zoom.us") ||
		shExpMatch(host, "*.zoom.us") ||		
		shExpMatch(host, "login.microsoftonline.com") ||
		shExpMatch(host, "login.windows.net") ||
		shExpMatch(host, "outlook.office365.com") ||
		shExpMatch(host, "outlook.office.com") ||
		shExpMatch(host, "autodiscover-s.outlook.com") ||
		shExpMatch(host, "lyncdiscover.johndeere.com") ||
		shExpMatch(host, "autodiscover.johndeere.com") ||
		shExpMatch(host, "email.johndeere.com") ||
		shExpMatch(host, "sip.johndeere.com") ||
		shExpMatch(host, "*.lync.com") ||
		shExpMatch(host, "*.skypeforbusiness.com") ||
		shExpMatch(host, "*.skype.com") ||
		shExpMatch(host, "login.live.com") ||
		shExpMatch(host, "*.officeapps.live.com") ||
		shExpMatch(host, "*.wg1.kontiki.com") ||
		shExpMatch(host, "secure.aadcdn.microsoftonline-p.com") ||
		shExpMatch(host, "client-office365-tas.msedge.net") ||
		shExpMatch(host, "config.edge.skype.com") ||
		shExpMatch(host, "contentstorage.osi.office.net") ||
		shExpMatch(host, "*.msauth.net") ||
		shExpMatch(host, ".pipe.aria.microsoft.com") ||
		shExpMatch(host, "go.microsoft.com") ||
		shExpMatch(host, "*.jetbrains.com") ||
		shExpMatch(host, "sfb*ext.johndeere.com") ||
		shExpMatch(host, "im.johndeere.com") ||
		shExpMatch(host, "im2.johndeere.com") ||
		shExpMatch(host, "*.mm.bing.net") ||
		shExpMatch(host, "jdvpn.johndeereandco.com") ||
		shExpMatch(host, "*.amazonappstream.com")||
		shExpMatch(host, "appstream2.us-east-1.aws.amazon.com")||
		shExpMatch(host, "appstream2.eu-central-1.aws.amazon.com")||
		shExpMatch(host, "us-east-1.signin.aws.amazon.com")||
		shExpMatch(host, "us-east-1.signin-reg.aws.amazon.com")||
	    shExpMatch(host, "services.mathworks.com")||
		shExpMatch(host, "esd.mathworks.com")||
		shExpMatch(host, "login.mathworks.com")||
		shExpMatch(host, "*.bancojohndeere.rsfn.net.br") ||
		shExpMatch(host, "id.articulate.com") ||
		shExpMatch(host, "api.articulate.com") ||
		shExpMatch(host, "cdn.articulate.com") ||
		shExpMatch(host, "id-metrics.articulate.com") ||
		shExpMatch(host, "solutions.sciquest.com") ||
		shExpMatch(host, "o365.workfront.com") ||
		shExpMatch(host, "*.dataservice.protection.outlook.com") ||
		shExpMatch(host, "*.aadrm.com") ||
		shExpMatch(host, "jdbp.ct.zootweb.eu") ||
		//MS update and o365 download failures
		shExpMatch(host, "enrollment.manage.microsoft.com") ||
		shExpMatch(host, "enterpriseregistration.windows.net") ||
		shExpMatch(host, "enterpriseenrollment.johndeere.com") ||
		//workfront outlook plugin
		shExpMatch(host, "o365.workfront.com") ||
		shExpMatch(host, "bridge.workfront.com") ||
		//
		shExpMatch(host, "*.postman.com") ||
		shExpMatch(host, "postman.com") ||
		shExpMatch(host, "*.cloudinary.com") ||
		shExpMatch(host, "dl.pstmn.io") ||
		shExpMatch(host, "*.johndeere.myshn.net"))
    return "DIRECT";

    //website is geo locked, send traffic to Frankfurt
    if (shExpMatch(host, "*.bionet.mvzlaborsaar.de") ||
        shExpMatch(host, "bionet.mvzlaborsaar.de"))
    return "PROXY 165.225.72.36:10364; PROXY 165.225.26.39:10364; DIRECT";

    
    if (shExpMatch(country,"China") &&
    //To resolve an issue over China Unicom
        shExpMatch(host, "*.sharepoint.com") ||
        shExpMatch(host, "*.onedrive.com") ||
        shExpMatch(host, "*.live.com") ||
        shExpMatch(host, "*.msftauth.net") ||
        shExpMatch(host, "*.cdn.office.net") ||
        shExpMatch(host, "*azurewebsites.net"))
    return "DIRECT";

    if (shExpMatch(country,"China"))
        // User is in China
    return "PROXY tsn1.sme.zscloud.net:10364; PROXY sha1.sme.zscloud.net:80; DIRECT";
    
    if (shExpMatch(country,"Israel")) 
      /* User is in Israel, send to Tel Aviv ZEN, use the next closest node as backup*/ 
    return "PROXY 94.188.131.32:80; PROXY 147.161.160.45:80; DIRECT";

    /*
    Forwarding HTTP and HTTPS to the US PZENs hosted at John Deere
    dedicated port 10364.
    */    
    if (shExpMatch(host, "johndeere.preprod.semafone.cloud") ||
		shExpMatch(host, "johndeere.semafone.cloud"))
    return "PROXY 192.43.68.128:10364; PROXY 204.54.33.128:10364; DIRECT";
    /*
    Forwarding HTTP and HTTPS to the nearest available ZEN on John Deere
    dedicated port 10364. The variables GATEWAY and SECONDARY_GATEWAY will 
    be replaced when the PAC file is fetched with the geographically closest
    datacenter VIP. Firewall rules must allow access to the specified port
    for all subnets listed at https://ips.zscloud.net/cenr.
    */
    return "PROXY 165.225.56.24:10364; PROXY 104.129.194.47:10364; DIRECT";
}