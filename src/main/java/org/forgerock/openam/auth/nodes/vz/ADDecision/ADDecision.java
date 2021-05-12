/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2021 ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes.vz.ADDecision;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.Hashtable;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Set;

import javax.inject.Inject;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.identity.idm.IdentityUtils;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * Node to check AD or ADLDS for authentication
 */
@Node.Metadata(outcomeProvider = ADDecision.ADOutcomeProvider.class, configClass = ADDecision.Config.class, tags = { "basic authn", "basic authentication" })
public class ADDecision implements Node {

	private final Logger logger = LoggerFactory.getLogger(ADDecision.class);
	private final Config config;
	private final IdentityUtils identityUtils;
	private final CoreWrapper coreWrapper;
	private static final String BUNDLE = ADDecision.class.getName();
	private boolean debugOn = false;

	/**
	 * Configuration for the node.
	 */
	public interface Config {
		/**
		 * Primary LDAP server configuration.
		 *
		 * @return the set
		 */
		@Attribute(order = 100, validators = { RequiredValueValidator.class })
		Set<String> primaryServers();

		/**
		 * Accounts search dn.
		 *
		 * @return the string
		 */
		@Attribute(order = 200)
		String baseDN();

		/**
		 * Specifies the LDAP connection mode.
		 *
		 * @return a {@link LdapConnectionMode} defining the connection mode.
		 */
		@Attribute(order = 300, validators = { RequiredValueValidator.class })
		default LdapConnectionMode ldapConnectionMode() {
			return LdapConnectionMode.LDAP;
		}

		/**
		 * Attribute used for AD Port.
		 *
		 * @return the string
		 */
		@Attribute(order = 400, validators = { RequiredValueValidator.class })
		String port();
		
        /**
         * Admin user dn.
         *
         * @return the string
         */
        @Attribute(order = 500, validators = {RequiredValueValidator.class})
        String adminDn();

        /**
         * Admin user password.
         *
         * @return the char [ ]
         */
        @Attribute(order = 600, validators = {RequiredValueValidator.class})
        @Password
        char[] adminPassword();
		
        /**
         * Username attribute.
         *
         * @return the string
         */
        @Attribute(order = 700, validators = {RequiredValueValidator.class})
        String userProfileAttribute();

	}

	/**
	 * Create the node using Guice injection. Just-in-time bindings can be used to
	 * obtain instances of other classes from the plugin.
	 *
	 * @param config The service config.
	 * @param realm  The realm the node is in.
	 * @throws NodeProcessException If the configuration was not valid.
	 */
	@Inject
	public ADDecision(@Assisted Config config, CoreWrapper coreWrapper, IdentityUtils identityUtils) throws NodeProcessException {
		this.config = config;
		this.coreWrapper = coreWrapper;
		this.identityUtils = identityUtils;
		if(logger.isDebugEnabled())
			this.debugOn = true;

	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		if(debugOn)
			logger.debug("Just entered AD Decision Node");
		JsonValue newState = context.sharedState.copy();
		final String realm = context.sharedState.get(REALM).asString();
		String uid = context.sharedState.get(USERNAME).asString();
		String pwd = context.transientState.get(PASSWORD).asString();
		
		if (pwd==null) {
			if(debugOn)
				logger.debug("In AD Decision Node, no password provided.");
			return goTo(LdapOutcome.FALSE).replaceSharedState(newState).build();
		}
			
		ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
		String ldapADServer = "";
		String ldapServerString = config.primaryServers().iterator().next();
		String thePort = config.port();
		switch (config.ldapConnectionMode()) {
		case LDAP:
			ldapADServer = "ldap://" + ldapServerString + ":" + thePort;
			break;
		case LDAPS:
			ldapADServer = "ldaps://" + ldapServerString + ":" + thePort;
		}
		
		
		String dn = lookupDN(config.adminDn(), config.adminPassword(), ldapADServer, config.baseDN(), config.userProfileAttribute(), uid);
		if (dn==null)
			return goTo(LdapOutcome.FALSE).replaceSharedState(newState).build();
		
		String result = authenticate(config.ldapConnectionMode(), config.primaryServers().iterator().next(), dn, pwd, config.port());
		if(debugOn)
			logger.debug("In AD Decision Node, here is the result:" + result + ".");
		
		ActionBuilder action = null;
		switch (result) {
		case "Passed": 
			action = goTo(LdapOutcome.TRUE);
			if(debugOn)
				logger.debug("In AD Decision Node, LDAPOutcome true");
			break;
		case "532":
			action = goTo(LdapOutcome.PWD_EXPIRED).withErrorMessage(bundle.getString("pwdExpired"));
			if(debugOn)
				logger.debug("In AD Decision Node, LDAPOutcome PWD_EXPIRED");
			break;
		case "533":
			action = goTo(LdapOutcome.ACT_DISABLED).withErrorMessage(bundle.getString("actDisabled"));
			if(debugOn)
				logger.debug("In AD Decision Node, LDAPOutcome ACT_DISABLED");
			break;
		case "701":
			action = goTo(LdapOutcome.ACT_EXPIRED).withErrorMessage(bundle.getString("actExpired"));
			if(debugOn)
				logger.debug("In AD Decision Node, LDAPOutcome ACT_EXPIRED");
			break;
		case "773":
			action = goTo(LdapOutcome.PWD_RESET_REQ).withErrorMessage(bundle.getString("pwdResetReq"));
			if(debugOn)
				logger.debug("In AD Decision Node, LDAPOutcome PWD_RESET_REQ");
			break;
		case "775":
			action = goTo(LdapOutcome.ACT_LOCKED).withErrorMessage(bundle.getString("actLocked")); 
			if(debugOn)
				logger.debug("In AD Decision Node, LDAPOutcome ACT_LOCKED");
			break;
		case "52e":
			action = goTo(LdapOutcome.FALSE);
			if(debugOn)
				logger.debug("In AD Decision Node, LDAPOutcome FALSE");
		}

		if (action==null) {
			action = goTo(LdapOutcome.FALSE);
			if(debugOn)
				logger.debug("In AD Decision Node, just found action==null"); 
		}
    	
		return action.replaceSharedState(newState).build();
	}
	
    private ActionBuilder goTo(LdapOutcome outcome) {
        return Action.goTo(outcome.name());
    }

	public String authenticate(LdapConnectionMode securityMode, String ldapServer, String uid, String pwd, String port) {
		String ldapADServer = "";
		String retCode = "Failed";
		
		switch (securityMode) {
		case LDAP:
			ldapADServer = "ldap://" + ldapServer + ":" + port;
			break;
		case LDAPS:
			ldapADServer = "ldaps://" + ldapServer + ":" + port;
		}

		Hashtable<String, Object> env = new Hashtable<String, Object>();
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		if (uid != null) {
			// logger.error("In AD Decision Node -> authenticate with uid: " + uid); 
			env.put(Context.SECURITY_PRINCIPAL, uid);
		}
		if (pwd != null) {
			//logger.error("In AD Decision Node -> authenticate with pwd: " + pwd); 
			env.put(Context.SECURITY_CREDENTIALS, pwd);
		}
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapADServer); 
		//logger.error("In AD Decision Node -> authenticate with ldapADServer: " + ldapADServer); 

		//env.put("com.sun.jndi.ldap.connect.pool", "true");  
		LdapContext ctx = null;

		try {
			ctx = new InitialLdapContext(env, null);
			retCode = "Passed";

		} catch (NamingException e) {

			retCode = getErrorCode(e); 
			logger.error("In AD Decision Node, and threw NamingException: " + e);  
		}

		finally {
			if (ctx != null) {
				try {
					ctx.close();
				} catch (NamingException e) { 
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		return retCode;

	}

	private String getErrorCode(NamingException e) {
		String retVal = "";
		if (e instanceof AuthenticationException) {
			String message = e.getMessage();
			retVal = (message.substring(message.indexOf("data") + 4, message.lastIndexOf(","))).trim(); 
		}

		return retVal;

	}
	
	public String lookupDN(String svUid, char[] svPwd, String ldapADServer, String baseDN, String attributeName, String userName) {

		String retVal = "";
		LdapContext ctx = null;
		NamingEnumeration<SearchResult> results = null;
		try {
			Hashtable<String, Object> env = new Hashtable<String, Object>();
			env.put(Context.SECURITY_AUTHENTICATION, "simple");
			env.put(Context.SECURITY_PRINCIPAL, svUid);
			env.put(Context.SECURITY_CREDENTIALS, svPwd);
			env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
			env.put(Context.PROVIDER_URL, ldapADServer);
			env.put("com.sun.jndi.ldap.connect.pool", "true");
			ctx = new InitialLdapContext(env, null);
			String searchFilter = "(" + attributeName + "=" + userName + ")";

			SearchControls searchControls = new SearchControls();
			searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
			searchControls.setCountLimit(1);

			results = ctx.search(baseDN, searchFilter, searchControls);

			if (results.hasMore()) {
				SearchResult result = (SearchResult) results.next();
				retVal = result.getNameInNamespace();
			} else {
				retVal = null;
			}
			results.close();
			ctx.close();
		} catch (NamingException e) {
			e.printStackTrace();
			logger.error(e.getMessage());
		} finally {
			try {
				if (results != null)
					results.close();

				if (ctx != null)
					ctx.close();
			} catch (NamingException e) {
				e.printStackTrace();
			}
		}

		return retVal;

	}
	

	/**
	 * Defines which protocol/operation is used to establish the connection to the
	 * LDAP Directory Server.
	 */
	public enum LdapConnectionMode {
		/**
		 * The connection won't be secured and passwords are transferred in cleartext
		 * over the network.
		 */
		LDAP,
		/**
		 * the connection is secured via SSL or TLS.
		 */
		LDAPS
	}

	/**
	 * The possible outcomes for the LdapDecisionNode.
	 */
	public enum LdapOutcome {
		/**
		 * Successful authentication.
		 */
		TRUE,
		/**
		 * Authentication failed.
		 */
		FALSE,
		/**
		 * The ldap user account password expired.
		 */
		PWD_EXPIRED,
		/**
		 * The ldap user's account disabled.
		 */
		ACT_DISABLED,

		ACT_EXPIRED,
		PWD_RESET_REQ,
		ACT_LOCKED
	}

	/**
	 * Defines the possible outcomes from this Ldap node.
	 */
	public static class ADOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(ADDecision.BUNDLE, ADOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(
                    new Outcome(LdapOutcome.TRUE.name(), bundle.getString("trueOutcome")),
                    new Outcome(LdapOutcome.FALSE.name(), bundle.getString("falseOutcome")),
                    new Outcome(LdapOutcome.PWD_EXPIRED.name(), bundle.getString("pwdExpiredOutcome")),
                    new Outcome(LdapOutcome.ACT_DISABLED.name(), bundle.getString("actDisabledOutcome")),
                    new Outcome(LdapOutcome.ACT_EXPIRED.name(), bundle.getString("actExpiredOutcome")),
                    new Outcome(LdapOutcome.PWD_RESET_REQ.name(), bundle.getString("pwdResetReqOutcome")),
                    new Outcome(LdapOutcome.ACT_LOCKED.name(), bundle.getString("actLockedOutcome")));
		}
	}	
}
