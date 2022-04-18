package org.wso2.carbon.is.migration.service.v5120.migrator;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.IdentityRegistryResources;
import org.wso2.carbon.identity.core.migrate.MigrationClientException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.is.migration.service.Migrator;
import org.wso2.carbon.is.migration.util.Constant;
import org.wso2.carbon.is.migration.util.ReportUtil;
import org.wso2.carbon.is.migration.util.Utility;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.jdbc.utils.Transaction;
import org.wso2.carbon.user.api.Tenant;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

import static org.wso2.carbon.is.migration.util.Constant.REPORT_PATH;

public class SAMLMetadataMigrator extends Migrator {

    private static final Logger log = LoggerFactory.getLogger(SAMLMetadataMigrator.class);
    private ReportUtil reportUtil;

    public static final String ISSUER = "issuer";
    public static final String ISSUER_QUALIFIER = "issuerQualifier";
    public static final String ASSERTION_CONSUMER_URLS = "assertionConsumerUrls";
    public static final String DEFAULT_ASSERTION_CONSUMER_URL = "defaultAssertionConsumerUrl";
    public static final String SIGNING_ALGORITHM_URI = "signingAlgorithmURI";
    public static final String DIGEST_ALGORITHM_URI = "digestAlgorithmURI";
    public static final String ASSERTION_ENCRYPTION_ALGORITHM_URI = "assertionEncryptionAlgorithmURI";
    public static final String KEY_ENCRYPTION_ALGORITHM_URI = "keyEncryptionAlgorithmURI";
    public static final String CERT_ALIAS = "certAlias";
    public static final String ATTRIBUTE_CONSUMING_SERVICE_INDEX = "attributeConsumingServiceIndex";
    public static final String DO_SIGN_RESPONSE = "doSignResponse";
    public static final String DO_SINGLE_LOGOUT = "doSingleLogout";
    public static final String DO_FRONT_CHANNEL_LOGOUT = "doFrontChannelLogout";
    public static final String FRONT_CHANNEL_LOGOUT_BINDING = "frontChannelLogoutBinding";
    public static final String IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED = "isAssertionQueryRequestProfileEnabled";
    public static final String SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES = "supportedAssertionQueryRequestTypes";
    public static final String ENABLE_SAML2_ARTIFACT_BINDING = "enableSAML2ArtifactBinding";
    public static final String DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE = "doValidateSignatureInArtifactResolve";
    public static final String LOGIN_PAGE_URL = "loginPageURL";
    public static final String SLO_RESPONSE_URL = "sloResponseURL";
    public static final String SLO_REQUEST_URL = "sloRequestURL";
    public static final String REQUESTED_CLAIMS = "requestedClaims";
    public static final String REQUESTED_AUDIENCES = "requestedAudiences";
    public static final String REQUESTED_RECIPIENTS = "requestedRecipients";
    public static final String ENABLE_ATTRIBUTES_BY_DEFAULT = "enableAttributesByDefault";
    public static final String NAME_ID_CLAIM_URI = "nameIdClaimUri";
    public static final String NAME_ID_FORMAT = "nameIDFormat";
    public static final String IDP_INIT_SSO_ENABLED = "idPInitSSOEnabled";
    public static final String IDP_INIT_SLO_ENABLED = "idPInitSLOEnabled";
    public static final String IDP_INIT_SLO_RETURN_TO_URLS = "idpInitSLOReturnToURLs";
    public static final String DO_ENABLE_ENCRYPTED_ASSERTION = "doEnableEncryptedAssertion";
    public static final String DO_VALIDATE_SIGNATURE_IN_REQUESTS = "doValidateSignatureInRequests";
    public static final String IDP_ENTITY_ID_ALIAS = "idpEntityIDAlias";

    public static final String SAML2 = "samlsso";
    public static final String STANDARD_APPLICATION = "standardAPP";

    public static final String ADD_SAML_APP = "INSERT INTO SP_INBOUND_AUTH (TENANT_ID, INBOUND_AUTH_KEY," +
            "INBOUND_AUTH_TYPE,PROP_NAME, PROP_VALUE, APP_ID,INBOUND_CONFIG_TYPE) VALUES (?,?,?,?,?,?,?)";
    public static final String CHECK_SAML_APP_EXISTS_BY_ISSUER = "SELECT * FROM SP_INBOUND_AUTH WHERE " +
            "INBOUND_AUTH_KEY = ? AND INBOUND_AUTH_TYPE = ? AND TENANT_ID = ? AND PROP_NAME != null LIMIT 1";
    public static final String GET_SP_APP_ID_BY_ISSUER = "SELECT APP_ID FROM SP_INBOUND_AUTH WHERE " +
            "INBOUND_AUTH_KEY = ? AND TENANT_ID = ? AND INBOUND_AUTH_TYPE = ?";


    @Override
    public void dryRun() throws MigrationClientException {
        log.info(Constant.MIGRATION_LOG + "Executing dry run for {}", this.getClass().getName());
        Properties migrationProperties = getMigratorConfig().getParameters();
        String reportPath = (String) migrationProperties.get(REPORT_PATH);

        try {
            reportUtil = new ReportUtil(reportPath);
            reportUtil.writeMessage("\n--- Summery of the report - SAML metadata Migration ---\n");
            reportUtil.writeMessage(
                    String.format("%40s | %40s | %40s | %40s", "Issuer ", "Key", "Value",
                            "Tenant Domain"));

            log.info(Constant.MIGRATION_LOG + "Started the dry run of SAML metadata migration.");
            // Migrate super tenant
            migratingSAMLMetadata(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, true);

            // Migrate other tenants
            Set<Tenant> tenants = Utility.getTenants();
            for (Tenant tenant : tenants) {
                if (isIgnoreForInactiveTenants() && !tenant.isActive()) {
                    log.info(Constant.MIGRATION_LOG + "Tenant " + tenant.getDomain() + " is inactive. SAML " +
                            "metadata migration will be skipped. ");
                } else {
                    migratingSAMLMetadata(tenant.getDomain(), true);
                }
            }
            reportUtil.commit();
        } catch (IOException e) {
            log.error(Constant.MIGRATION_LOG + "Error while constructing the DryRun report.", e);
        }


    }

    @Override
    public void migrate() throws MigrationClientException {
        // Migrate super tenant
        migratingSAMLMetadata(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, false);

        // Migrate other tenants
        Set<Tenant> tenants = Utility.getTenants();
        for (Tenant tenant : tenants) {
            if (isIgnoreForInactiveTenants() && !tenant.isActive()) {
                log.info(Constant.MIGRATION_LOG + "Tenant " + tenant.getDomain() + " is inactive. SAML " +
                        "metadata migration will be skipped. ");
            } else {
                migratingSAMLMetadata(tenant.getDomain(), false);
            }
        }
    }

    private void migratingSAMLMetadata(String tenantDomain, boolean isDryRun) throws MigrationClientException {
        log.info("............................................................................................");
        if (isDryRun) {
            log.info(Constant.MIGRATION_LOG + "Started dry run of migrating SAML metadata for tenant: " + tenantDomain);
        } else {
            log.info(Constant.MIGRATION_LOG + "Started migrating SAML metadata for tenant: " + tenantDomain);
        }

        SAMLSSOServiceProviderDO[] samlssoServiceProviders = null;

        int tenantId;
        Registry registry;
        if (StringUtils.isEmpty(tenantDomain)) {
            if (log.isDebugEnabled()) {
                log.debug("Tenant domain is not available. Hence using super tenant domain");
            }
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            tenantId = MultitenantConstants.SUPER_TENANT_ID;
        } else {
            tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        }

        try {
            IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            registry = IdentityTenantUtil.getConfigRegistry(tenantId);
            samlssoServiceProviders = getServiceProviders(registry);
            if(!isDryRun) {
                removeAllServiceProvidersFromRegistry(registry,tenantId);
            }
        } catch (RegistryException e) {
            log.error(Constant.MIGRATION_LOG + "Error while getting data from the registry.", e);
        } catch (IdentityException e) {
            log.error(Constant.MIGRATION_LOG + "Error while initializing the registry for : " + tenantDomain, e);
        }

        if (samlssoServiceProviders == null) {
            log.info(Constant.MIGRATION_LOG + "There are no SAML Service Providers configured for the tenant: "
                    + tenantDomain);
            return;
        }
        for(SAMLSSOServiceProviderDO samlssoServiceProviderDO : samlssoServiceProviders) {
            try {
                addServiceProvider(samlssoServiceProviderDO, tenantId ,isDryRun);
            } catch (IdentityException e) {
                e.printStackTrace();
                log.error(Constant.MIGRATION_LOG + "Error while persisting data to the database.", e);
            }
        }
    }

    private void removeAllServiceProvidersFromRegistry(Registry registry , int tenantId) throws IdentityException {
        String path = IdentityRegistryResources.SAML_SSO_SERVICE_PROVIDERS;
        boolean isTransactionStarted = Transaction.isStarted();
        boolean isErrorOccurred = false;
        try {
            if (!registry.resourceExists(path)) {
                if (log.isDebugEnabled()) {
                    log.debug("Registry resource does not exist for the path: " + path);
                }
                return;
            }
            if (!isTransactionStarted) {
                registry.beginTransaction();
            }
            registry.delete(path);
            return;
        } catch (RegistryException e) {
            isErrorOccurred = true;
            String msg = "Error removing the service providers with tenantId : "+tenantId;
            log.error(msg, e);
            throw IdentityException.error(msg, e);
        } finally {
            commitOrRollbackTransaction(registry, isErrorOccurred);
        }
    }

    /**
     * Commit or rollback the registry operation depends on the error condition.
     * @param isErrorOccurred Identifier for error transactions.
     * @throws IdentityException Error while committing or running rollback on the transaction.
     */
    private void commitOrRollbackTransaction(Registry registry, boolean isErrorOccurred) throws IdentityException {

        try {
            // Rollback the transaction if there is an error, Otherwise try to commit.
            if (isErrorOccurred) {
                registry.rollbackTransaction();
            } else {
                registry.commitTransaction();
            }
        } catch (RegistryException ex) {
            throw new IdentityException("Error occurred while trying to commit or rollback the registry operation.", ex);
        }
    }

    private SAMLSSOServiceProviderDO[] getServiceProviders(Registry registry) throws IdentityException {
        List<SAMLSSOServiceProviderDO> serviceProvidersList = new ArrayList<>();
        try {
            if (registry.resourceExists(IdentityRegistryResources.SAML_SSO_SERVICE_PROVIDERS)) {
                Resource samlSSOServiceProvidersResource = registry.get(IdentityRegistryResources
                        .SAML_SSO_SERVICE_PROVIDERS);
                if (samlSSOServiceProvidersResource instanceof Collection) {
                    Collection samlSSOServiceProvidersCollection = (Collection) samlSSOServiceProvidersResource;
                    String[] resources = samlSSOServiceProvidersCollection.getChildren();
                    for (String resource : resources) {
                        getChildResources(registry, resource, serviceProvidersList);
                    }
                }
            }
        } catch (RegistryException e) {
            log.error("Error reading Service Providers from Registry", e);
            throw IdentityException.error("Error reading Service Providers from Registry", e);
        }
        return serviceProvidersList.toArray(new SAMLSSOServiceProviderDO[0]);
    }

    private void getChildResources(Registry registry, String parentResource, List<SAMLSSOServiceProviderDO> serviceProviderList) throws RegistryException {
        if (registry.resourceExists(parentResource)) {
            Resource resource = registry.get(parentResource);
            if (resource instanceof Collection) {
                Collection collection = (Collection) resource;
                String[] resources = collection.getChildren();
                String[] var6 = resources;
                int var7 = resources.length;

                for (int var8 = 0; var8 < var7; ++var8) {
                    String res = var6[var8];
                    this.getChildResources(registry, res, serviceProviderList);
                }
            } else {
                serviceProviderList.add(this.resourceToObject(resource));
            }
        }

    }

    private SAMLSSOServiceProviderDO resourceToObject(Resource resource) {
        SAMLSSOServiceProviderDO serviceProviderDO = new SAMLSSOServiceProviderDO();
        serviceProviderDO.setIssuer(resource.getProperty("Issuer"));
        serviceProviderDO.setAssertionConsumerUrls(resource.getPropertyValues("SAMLSSOAssertionConsumerURLs"));
        serviceProviderDO.setDefaultAssertionConsumerUrl(resource.getProperty("DefaultSAMLSSOAssertionConsumerURL"));
        serviceProviderDO.setCertAlias(resource.getProperty("IssuerCertAlias"));
        if (StringUtils.isNotEmpty(resource.getProperty("signingAlgorithm"))) {
            serviceProviderDO.setSigningAlgorithmUri(resource.getProperty("signingAlgorithm"));
        }

        if (resource.getProperty("AssertionQueryRequestProfileEnabled") != null) {
            serviceProviderDO.setAssertionQueryRequestProfileEnabled(Boolean.valueOf(resource.getProperty("AssertionQueryRequestProfileEnabled").trim()));
        }

        if (resource.getProperty("SupportedAssertionQueryRequestTypes") != null) {
            serviceProviderDO.setSupportedAssertionQueryRequestTypes(resource.getProperty("SupportedAssertionQueryRequestTypes").trim());
        }

        if (resource.getProperty("EnableSAML2ArtifactBinding") != null) {
            serviceProviderDO.setEnableSAML2ArtifactBinding(Boolean.valueOf(resource.getProperty("EnableSAML2ArtifactBinding").trim()));
        }

        if (StringUtils.isNotEmpty(resource.getProperty("digestAlgorithm"))) {
            serviceProviderDO.setDigestAlgorithmUri(resource.getProperty("digestAlgorithm"));
        }

        if (StringUtils.isNotEmpty(resource.getProperty("assertionEncryptionAlgorithm"))) {
            serviceProviderDO.setAssertionEncryptionAlgorithmUri(resource.getProperty("assertionEncryptionAlgorithm"));
        }

        if (StringUtils.isNotEmpty(resource.getProperty("keyEncryptionAlgorithm"))) {
            serviceProviderDO.setKeyEncryptionAlgorithmUri(resource.getProperty("keyEncryptionAlgorithm"));
        }

        if (resource.getProperty("doSingleLogout") != null) {
            serviceProviderDO.setDoSingleLogout(Boolean.valueOf(resource.getProperty("doSingleLogout").trim()));
        }

        if (resource.getProperty("NameIDFormat") != null) {
            serviceProviderDO.setNameIDFormat(resource.getProperty("NameIDFormat"));
        }

        if (resource.getProperty("EnableNameIDClaimUri") != null && Boolean.valueOf(resource.getProperty("EnableNameIDClaimUri").trim())) {
            serviceProviderDO.setNameIdClaimUri(resource.getProperty("NameIDClaimUri"));
        }

        serviceProviderDO.setLoginPageURL(resource.getProperty("loginPageURL"));
        if (resource.getProperty("doSignResponse") != null) {
            serviceProviderDO.setDoSignResponse(Boolean.valueOf(resource.getProperty("doSignResponse").trim()));
        }

        if (serviceProviderDO.isDoSingleLogout()) {
            serviceProviderDO.setSloResponseURL(resource.getProperty("sloResponseURL"));
            serviceProviderDO.setSloRequestURL(resource.getProperty("sloRequestURL"));
            if (resource.getProperty("doFrontChannelLogout") != null) {
                serviceProviderDO.setDoFrontChannelLogout(Boolean.valueOf(resource.getProperty("doFrontChannelLogout").trim()));
                if (serviceProviderDO.isDoFrontChannelLogout()) {
                    if (resource.getProperty("frontChannelLogoutBinding") != null) {
                        serviceProviderDO.setFrontChannelLogoutBinding(resource.getProperty("frontChannelLogoutBinding"));
                    } else {
                        serviceProviderDO.setFrontChannelLogoutBinding("HTTPRedirectBinding");
                    }
                }
            }
        }

        if (resource.getProperty("doSignAssertions") != null) {
            serviceProviderDO.setDoSignAssertions(Boolean.valueOf(resource.getProperty("doSignAssertions").trim()));
        }

        if (resource.getProperty("EnableSAMLECP") != null) {
            serviceProviderDO.setSamlECP(Boolean.valueOf(resource.getProperty("EnableSAMLECP").trim()));
        }

        if (resource.getProperty("AttributeConsumingServiceIndex") != null) {
            serviceProviderDO.setAttributeConsumingServiceIndex(resource.getProperty("AttributeConsumingServiceIndex"));
        } else {
            serviceProviderDO.setAttributeConsumingServiceIndex("");
        }

        if (resource.getProperty("RequestedClaims") != null) {
            serviceProviderDO.setRequestedClaims(resource.getPropertyValues("RequestedClaims"));
        }

        if (resource.getProperty("RequestedAudiences") != null) {
            serviceProviderDO.setRequestedAudiences(resource.getPropertyValues("RequestedAudiences"));
        }

        if (resource.getProperty("RequestedRecipients") != null) {
            serviceProviderDO.setRequestedRecipients(resource.getPropertyValues("RequestedRecipients"));
        }

        if (resource.getProperty("EnableAttributesByDefault") != null) {
            String enableAttrByDefault = resource.getProperty("EnableAttributesByDefault");
            serviceProviderDO.setEnableAttributesByDefault(Boolean.valueOf(enableAttrByDefault));
        }

        if (resource.getProperty("IdPInitSSOEnabled") != null) {
            serviceProviderDO.setIdPInitSSOEnabled(Boolean.valueOf(resource.getProperty("IdPInitSSOEnabled").trim()));
        }

        if (resource.getProperty("IdPInitSLOEnabled") != null) {
            serviceProviderDO.setIdPInitSLOEnabled(Boolean.valueOf(resource.getProperty("IdPInitSLOEnabled").trim()));
            if (serviceProviderDO.isIdPInitSLOEnabled() && resource.getProperty("IdPInitiatedSLOReturnToURLs") != null) {
                serviceProviderDO.setIdpInitSLOReturnToURLs(resource.getPropertyValues("IdPInitiatedSLOReturnToURLs"));
            }
        }

        if (resource.getProperty("doEnableEncryptedAssertion") != null) {
            serviceProviderDO.setDoEnableEncryptedAssertion(Boolean.valueOf(resource.getProperty("doEnableEncryptedAssertion").trim()));
        }

        if (resource.getProperty("doValidateSignatureInRequests") != null) {
            serviceProviderDO.setDoValidateSignatureInRequests(Boolean.valueOf(resource.getProperty("doValidateSignatureInRequests").trim()));
        }

        if (resource.getProperty("doValidateSignatureInArtifactResolve") != null) {
            serviceProviderDO.setDoValidateSignatureInArtifactResolve(Boolean.valueOf(resource.getProperty("doValidateSignatureInArtifactResolve").trim()));
        }

        if (resource.getProperty("SpQualifier") != null) {
            serviceProviderDO.setIssuerQualifier(resource.getProperty("SpQualifier"));
        }

        if (resource.getProperty("IdPEntityIDAlias") != null) {
            serviceProviderDO.setIdpEntityIDAlias(resource.getProperty("IdPEntityIDAlias"));
        }

        return serviceProviderDO;
    }

    /**
     * Add the service provider information to the database.
     *
     * @param serviceProviderDO Service provider information object.
     * @param isDryRun
     * @return True if addition successful.
     * @throws IdentityException Error while persisting to the database.
     */
    private boolean addServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO, int tenantId, boolean isDryRun) throws IdentityException {

        if (serviceProviderDO == null || serviceProviderDO.getIssuer() == null ||
                StringUtils.isBlank(serviceProviderDO.getIssuer())) {
            throw new IdentityException("Issuer cannot be found in the provided arguments.");
        }

        // If an issuer qualifier value is specified, it is appended to the end of the issuer value.
        if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
            serviceProviderDO.setIssuer(getIssuerWithQualifier(serviceProviderDO.getIssuer(),
                    serviceProviderDO.getIssuerQualifier()));
        }

        if (isServiceProviderExists(serviceProviderDO.getIssuer(),tenantId)) {
            if (log.isDebugEnabled()) {
                if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
                    log.debug("SAML2 Service Provider already exists with the same issuer name "
                            + getIssuerWithoutQualifier(serviceProviderDO.getIssuer()) + " and qualifier name "
                            + serviceProviderDO.getIssuerQualifier());
                } else {
                    log.debug("SAML2 Service Provider already exists with the same issuer name "
                            + serviceProviderDO.getIssuer());
                }
            }
            return false;
        }

        HashMap<String, LinkedHashSet<String>> pairMap = convertServiceProviderDOToMap(serviceProviderDO);
        String issuerName = serviceProviderDO.getIssuer();

        int appId = getServiceProviderAppId(issuerName, tenantId);

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);

        PreparedStatement prepStmt = null;

        try {
            prepStmt = connection.prepareStatement(ADD_SAML_APP);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, issuerName);
            prepStmt.setString(3,SAML2);
            prepStmt.setInt(6, appId);
            prepStmt.setString(7, STANDARD_APPLICATION);
            for (Map.Entry<String, LinkedHashSet<String>> entry : pairMap.entrySet()) {
                for (String value : entry.getValue()) {
                    if(isDryRun) {
                        reportUtil.writeMessage(String.format("%40s | %40s | %40s | %40s ", issuerName,
                                entry.getKey(), value, tenantId));
                    }
                    else {
                        prepStmt.setString(4, entry.getKey());
                        prepStmt.setString(5, value);
                        prepStmt.addBatch();
                    }
                }
            }
            prepStmt.executeBatch();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            String msg = "Error adding new service provider to the database with issuer" +
                    serviceProviderDO.getIssuer() + " , and AppID = "+appId+", and prepareStatement = "+prepStmt.toString();
            log.error(msg, e);
            throw new IdentityException(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return true;
    }

    /**
     * Get the issuer value to be added to registry by appending the qualifier.
     *
     * @param issuer value given as 'issuer' when configuring SAML SP.
     * @return issuer value with qualifier appended.
     */
    private String getIssuerWithQualifier(String issuer, String qualifier) {

        String issuerWithQualifier = issuer + IdentityRegistryResources.QUALIFIER_ID + qualifier;
        return issuerWithQualifier;
    }

    private boolean isServiceProviderExists(String issuer, int tenantId) throws IdentityException {

        PreparedStatement prepStmt = null;
        ResultSet results = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);

        try {
            prepStmt = connection.prepareStatement(CHECK_SAML_APP_EXISTS_BY_ISSUER);
            prepStmt.setString(1, issuer);
            prepStmt.setString(2, SAML2);
            prepStmt.setInt(3, tenantId);
            results = prepStmt.executeQuery();
            if (results.next()) {
                return true;
            }
        } catch (SQLException e) {
            String msg = "Error checking service provider from the database with issuer : " + issuer;
            log.error(msg, e);
            throw new IdentityException(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, results, prepStmt);
        }
        return false;
    }

    private int getServiceProviderAppId(String issuer, int tenantId) throws IdentityException {

        PreparedStatement prepStmt = null;
        ResultSet results = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        String resultsMsg = null;
        try {
            prepStmt = connection.prepareStatement(GET_SP_APP_ID_BY_ISSUER);
            prepStmt.setString(1, issuer);
            prepStmt.setInt(2, tenantId);
            prepStmt.setString(3, SAML2);
            results = prepStmt.executeQuery();
            if (results.next()) {
                String msg = "My Results = "+ results.toString();
                log.error(msg);
                return results.getInt(1);
            }
        } catch (SQLException e) {
            String msg = "Error checking service provider from the database with issuer : " + issuer +
                    " , prepareStatement = "+prepStmt.toString()+" results = "+((resultsMsg == null)?"null":resultsMsg);
            throw new IdentityException(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, results, prepStmt);
        }
        return -99999;
    }

    /**
     * Get the issuer value by removing the qualifier.
     *
     * @param issuerWithQualifier issuer value saved in the registry.
     * @return issuer value given as 'issuer' when configuring SAML SP.
     */
    private String getIssuerWithoutQualifier(String issuerWithQualifier) {

        String issuerWithoutQualifier = StringUtils.substringBeforeLast(issuerWithQualifier,
                IdentityRegistryResources.QUALIFIER_ID);
        return issuerWithoutQualifier;
    }

    private HashMap<String, LinkedHashSet<String>> convertServiceProviderDOToMap(SAMLSSOServiceProviderDO
                                                                                         serviceProviderDO) {
        HashMap<String, LinkedHashSet<String>> pairMap = new HashMap<>();
        addKeyValuePair(pairMap, ISSUER, serviceProviderDO.getIssuer());
        addKeyValuePair(pairMap, ISSUER_QUALIFIER, serviceProviderDO.getIssuerQualifier());
        for (String url : serviceProviderDO.getAssertionConsumerUrls()) {
            addKeyValuePair(pairMap, ASSERTION_CONSUMER_URLS, url);
        }
        addKeyValuePair(pairMap, DEFAULT_ASSERTION_CONSUMER_URL, serviceProviderDO.getDefaultAssertionConsumerUrl());
        addKeyValuePair(pairMap, SIGNING_ALGORITHM_URI, serviceProviderDO.getSigningAlgorithmUri());
        addKeyValuePair(pairMap, DIGEST_ALGORITHM_URI, serviceProviderDO.getDigestAlgorithmUri());
        addKeyValuePair(pairMap, ASSERTION_ENCRYPTION_ALGORITHM_URI,
                serviceProviderDO.getAssertionEncryptionAlgorithmUri());
        addKeyValuePair(pairMap, KEY_ENCRYPTION_ALGORITHM_URI, serviceProviderDO.getKeyEncryptionAlgorithmUri());
        addKeyValuePair(pairMap, CERT_ALIAS, serviceProviderDO.getCertAlias());
        addKeyValuePair(pairMap, ATTRIBUTE_CONSUMING_SERVICE_INDEX,
                serviceProviderDO.getAttributeConsumingServiceIndex());
        addKeyValuePair(pairMap, DO_SIGN_RESPONSE, serviceProviderDO.isDoSignResponse() ? "true" : "false");
        addKeyValuePair(pairMap, DO_SINGLE_LOGOUT, serviceProviderDO.isDoSingleLogout() ? "true" : "false");
        addKeyValuePair(pairMap, DO_FRONT_CHANNEL_LOGOUT,
                serviceProviderDO.isDoFrontChannelLogout() ? "true" : "false");
        addKeyValuePair(pairMap, FRONT_CHANNEL_LOGOUT_BINDING, serviceProviderDO.getFrontChannelLogoutBinding());
        addKeyValuePair(pairMap, IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED,
                serviceProviderDO.isAssertionQueryRequestProfileEnabled() ? "true" : "false");
        addKeyValuePair(pairMap, SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES,
                serviceProviderDO.getSupportedAssertionQueryRequestTypes());
        addKeyValuePair(pairMap, ENABLE_SAML2_ARTIFACT_BINDING,
                serviceProviderDO.isEnableSAML2ArtifactBinding() ? "true" : "false");
        addKeyValuePair(pairMap, DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE,
                serviceProviderDO.isDoValidateSignatureInArtifactResolve() ? "true" : "false");
        addKeyValuePair(pairMap, LOGIN_PAGE_URL, serviceProviderDO.getLoginPageURL());
        addKeyValuePair(pairMap, SLO_RESPONSE_URL, serviceProviderDO.getSloResponseURL());
        addKeyValuePair(pairMap, SLO_REQUEST_URL, serviceProviderDO.getSloRequestURL());
        for (String claim : serviceProviderDO.getRequestedClaims()) {
            addKeyValuePair(pairMap, REQUESTED_CLAIMS, claim);
        }
        for (String audience : serviceProviderDO.getRequestedAudiences()) {
            addKeyValuePair(pairMap, REQUESTED_AUDIENCES, audience);
        }
        for (String recipient : serviceProviderDO.getRequestedRecipients()) {
            addKeyValuePair(pairMap, REQUESTED_RECIPIENTS, recipient);
        }
        addKeyValuePair(pairMap, ENABLE_ATTRIBUTES_BY_DEFAULT,
                serviceProviderDO.isEnableAttributesByDefault() ? "true" : "false");
        addKeyValuePair(pairMap, NAME_ID_CLAIM_URI, serviceProviderDO.getNameIdClaimUri());
        addKeyValuePair(pairMap, NAME_ID_FORMAT, serviceProviderDO.getNameIDFormat());
        addKeyValuePair(pairMap, IDP_INIT_SSO_ENABLED, serviceProviderDO.isIdPInitSSOEnabled() ? "true" : "false");
        addKeyValuePair(pairMap, IDP_INIT_SLO_ENABLED, serviceProviderDO.isIdPInitSLOEnabled() ? "true" : "false");
        for (String url : serviceProviderDO.getIdpInitSLOReturnToURLs()) {
            addKeyValuePair(pairMap, IDP_INIT_SLO_RETURN_TO_URLS, url);
        }
        addKeyValuePair(pairMap, DO_ENABLE_ENCRYPTED_ASSERTION,
                serviceProviderDO.isDoEnableEncryptedAssertion() ? "true" : "false");
        addKeyValuePair(pairMap, DO_VALIDATE_SIGNATURE_IN_REQUESTS,
                serviceProviderDO.isDoValidateSignatureInRequests() ? "true" : "false");
        addKeyValuePair(pairMap, IDP_ENTITY_ID_ALIAS, serviceProviderDO.getIdpEntityIDAlias());
        return pairMap;
    }

    private void addKeyValuePair(HashMap<String, LinkedHashSet<String>> map, String key, String value) {
        LinkedHashSet<String> values;
        if (map.containsKey(key)) {
            values = map.get(key);
        } else {
            values = new LinkedHashSet<>();
        }
        values.add(value);
        map.put(key, values);
    }
}
