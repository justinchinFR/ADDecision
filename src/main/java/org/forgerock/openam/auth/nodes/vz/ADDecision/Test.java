package org.forgerock.openam.auth.nodes.vz.ADDecision;

import java.util.Date;

import javax.naming.NamingException;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.nodes.vz.ADDecision.ADDecision.LdapConnectionMode;

public class Test {

	public static void main(String[] args) throws NamingException {
		Date startD = new Date();

		try {

			final String ldapAdServer = "dc1.fmad.frdpcloud.org";
			final String uPN = "@fmad.frdpcloud.org";

			final String ldapUsername = "amazur";
			final String ldapPassword = "Frdp-2010";

			ADDecision add = new ADDecision(null, null, null);

			//String result = add.authenticate(LdapConnectionMode.LDAP, ldapAdServer, uPN, ldapUsername, ldapPassword, "389");
			
			String ldapADServer = "ldap://" + ldapAdServer + ":389";
			char[] pwd = { 'F', 'r', 'd', 'p', '-', '2', '0', '1', '0' };
			
			String result = add.lookupDN("CN=Administrator,CN=Users,DC=fmad,DC=frdpcloud,DC=org", pwd, ldapADServer, "OU=Testing,DC=fmad,DC=frdpcloud,DC=org", "sAMAccountName", "amazur");
			result = add.authenticate(LdapConnectionMode.LDAP, ldapAdServer, result, ldapPassword, "389");
			System.out.println(result);

		} catch (NodeProcessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Date endD = new Date();

		long result = endD.getTime()-startD.getTime();
		System.out.println("run time " + result);

	}

}
