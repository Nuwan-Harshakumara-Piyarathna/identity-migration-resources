package org.wso2.carbon.is.migration.service.v5120.migrator;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.IdentityRegistryResources;
import org.wso2.carbon.identity.core.migrate.MigrationClientException;
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
import java.util.Properties;
import java.util.Set;

import static org.wso2.carbon.is.migration.util.Constant.REPORT_PATH;

/**
 * This class handles the SAML Metadata migration.
 */
public class SAMLMetadataMigrator extends Migrator {

    private static final Logger log = LoggerFactory.getLogger(SAMLMetadataMigrator.class);
    private ReportUtil reportUtil;

    public static final String SAML2 = "samlsso";
    public static final String STANDARD_APPLICATION = "standardAPP";

    public static final String ADD_SAML_APP = "INSERT INTO SP_INBOUND_AUTH (TENANT_ID, INBOUND_AUTH_KEY," +
            "INBOUND_AUTH_TYPE,PROP_NAME, PROP_VALUE, APP_ID,INBOUND_CONFIG_TYPE) VALUES (?,?,?,?,?,?,?)";
    public static final String CHECK_SAML_APP_EXISTS_BY_ISSUER = "SELECT * FROM SP_INBOUND_AUTH WHERE " +
            "INBOUND_AUTH_KEY = ? AND INBOUND_AUTH_TYPE = ? AND TENANT_ID = ? AND PROP_NAME = ? LIMIT 1";
    public static final String GET_SP_APP_ID_BY_ISSUER = "SELECT APP_ID FROM SP_INBOUND_AUTH WHERE " +
            "INBOUND_AUTH_KEY = ? AND TENANT_ID = ? AND INBOUND_AUTH_TYPE = ?";

    public final static String ISSUER = "Issuer";
    public final static String ISSUER_QUALIFIER = "SpQualifier";
    public final static String ASSERTION_CONSUMER_URLS = "SAMLSSOAssertionConsumerURLs";
    public final static String DEFAULT_ASSERTION_CONSUMER_URL = "DefaultSAMLSSOAssertionConsumerURL";
    public final static String ISSUER_CERT_ALIAS = "IssuerCertAlias";
    public final static String DO_SINGLE_LOGOUT = "doSingleLogout";
    public final static String DO_FRONT_CHANNEL_LOGOUT = "doFrontChannelLogout";
    public final static String FRONT_CHANNEL_LOGOUT_BINDING = "frontChannelLogoutBinding";
    public final static String DEFAULT_FRONT_CHANNEL_LOGOUT_BINDING = "HTTPRedirectBinding";
    public final static String SLO_RESPONSE_URL = "sloResponseURL";
    public final static String SLO_REQUEST_URL = "sloRequestURL";
    public final static String LOGIN_PAGE_URL = "loginPageURL";
    public final static String DO_SIGN_RESPONSE = "doSignResponse";
    public final static String DO_SIGN_ASSERTIONS = "doSignAssertions";
    public static final String REQUESTED_CLAIMS = "RequestedClaims";
    public static final String REQUESTED_AUDIENCES = "RequestedAudiences";
    public static final String REQUESTED_RECIPIENTS = "RequestedRecipients";
    public static final String ENABLE_ATTRIBUTES_BY_DEFAULT = "EnableAttributesByDefault";
    public static final String ENABLE_NAME_ID_CLAIM_URI = "EnableNameIDClaimUri";
    public static final String NAME_ID_CLAIM_URI = "NameIDClaimUri";
    public static final String NAME_ID_FORMAT = "NameIDFormat";
    public static final String IDP_INIT_SSO_ENABLED = "IdPInitSSOEnabled";
    public static final String IDP_INIT_SLO_ENABLED = "IdPInitSLOEnabled";
    public static final String IDP_INIT_SLO_RETURN_URLS = "IdPInitiatedSLOReturnToURLs";
    public static final String ENABLE_ENCRYPTED_ASSERTION = "doEnableEncryptedAssertion";
    public static final String VALIDATE_SIGNATURE_IN_REQUESTS = "doValidateSignatureInRequests";
    public static final String VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE = "doValidateSignatureInArtifactResolve";
    public static final String SIGNING_ALGORITHM = "signingAlgorithm";
    public static final String DIGEST_ALGORITHM = "digestAlgorithm";
    public static final String ASSERTION_ENCRYPTION_ALGORITHM = "assertionEncryptionAlgorithm";
    public static final String KEY_ENCRYPTION_ALGORITHM = "keyEncryptionAlgorithm";
    public static final String ASSERTION_QUERY_REQUEST_PROFILE_ENABLED = "AssertionQueryRequestProfileEnabled";
    public static final String SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES = "SupportedAssertionQueryRequestTypes";
    public static final String ENABLE_SAML2_ARTIFACT_BINDING = "EnableSAML2ArtifactBinding";
    public static final String ENABLE_ECP = "EnableSAMLECP";
    public static final String IDP_ENTITY_ID_ALIAS = "IdPEntityIDAlias";
    public static final String ATTRIBUTE_CONSUMING_SERVICE_INDEX = "AttributeConsumingServiceIndex";

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
            throw new MigrationClientException("Error while constructing the DryRun report.", e);
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
            IdentityTenantUtil.initializeRegistry(tenantId);
            registry = IdentityTenantUtil.getConfigRegistry(tenantId);
            moveServiceProvidersToRegistry(registry, tenantId, isDryRun, tenantDomain);
            if (!isDryRun) {
                removeAllServiceProvidersFromRegistry(registry, tenantId);
            }
        } catch (RegistryException e) {
            log.error(Constant.MIGRATION_LOG + "Error while getting data from the registry.", e);
            throw new MigrationClientException("Error while getting data from the registry.", e);
        } catch (IdentityException e) {
            log.error(Constant.MIGRATION_LOG + "Error while initializing the registry for : " + tenantDomain, e);
            throw new MigrationClientException("Error while initializing the registry for : " + tenantDomain, e);
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
        } catch (RegistryException e) {
            isErrorOccurred = true;
            String msg = "Error removing the service providers with tenantId : " + tenantId;
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
            throw new IdentityException("Error occurred while trying to commit or rollback the registry operation.",
                    ex);
        }
    }

    private void moveServiceProvidersToRegistry(Registry registry, int tenantId, boolean isDryRun, String tenantDomain)
            throws IdentityException {
        try {
            if (registry.resourceExists(IdentityRegistryResources.SAML_SSO_SERVICE_PROVIDERS)) {
                Resource samlSSOServiceProvidersResource = registry.get(IdentityRegistryResources
                        .SAML_SSO_SERVICE_PROVIDERS);
                if (samlSSOServiceProvidersResource instanceof Collection) {
                    Collection samlSSOServiceProvidersCollection = (Collection) samlSSOServiceProvidersResource;
                    String[] resources = samlSSOServiceProvidersCollection.getChildren();
                    if (resources.length == 0) {
                        log.info(Constant.MIGRATION_LOG + "There are no SAML Service Providers configured for " +
                                "the tenant: "
                                + tenantDomain);
                        return;
                    }
                    for (String resource : resources) {
                        getChildResources(registry, resource, tenantId, isDryRun);
                    }
                }
            }
        } catch (RegistryException e) {
            log.error("Error reading Service Providers from Registry", e);
            throw IdentityException.error("Error reading Service Providers from Registry", e);
        }
    }

    private void getChildResources(Registry registry, String parentResource, int tenantId, boolean isDryRun) throws
            RegistryException, IdentityException {
        if (registry.resourceExists(parentResource)) {
            Resource resource = registry.get(parentResource);
            if (resource instanceof Collection) {
                Collection collection = (Collection) resource;
                String[] resources = collection.getChildren();
                String[] var6 = resources;
                int var7 = resources.length;

                for (int var8 = 0; var8 < var7; ++var8) {
                    String res = var6[var8];
                    this.getChildResources(registry, res, tenantId, isDryRun);
                }
            } else {
                this.persistResourceAsKeyValuePairs(resource, tenantId, isDryRun);
            }
        }

    }

    private void persistResourceAsKeyValuePairs(Resource resource, int tenantId, boolean isDryRun)
            throws IdentityException {
        String issuer = resource.getProperty(ISSUER);
        String issuerQualifier = resource.getProperty(ISSUER_QUALIFIER);

        if (issuer == null ||
                StringUtils.isBlank(issuer)) {
            throw new IdentityException("Issuer cannot be found in the provided arguments.");
        }

        int appId = getServiceProviderAppId(issuer, tenantId);
        String issuerWithoutQualifier = getIssuerWithoutQualifier(issuer);
        if (appId == -1) {
            String msg = "";
            if (StringUtils.isNotBlank(issuerQualifier)) {
                msg = String.format("Cannot Find a ServiceProvider with the issuer Name : %s, Qualifier Name : %s, and tenantId : %d",
                        issuerWithoutQualifier, issuerQualifier, tenantId);
            } else {
                msg = String.format("SAML2 Service Provider already exists with the same issuer name %s, and " +
                        "tenantId : %d", issuer, tenantId);
            }
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            throw new IdentityException(msg);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);

        PreparedStatement prepStmt = null;

        if (isSAMLIssuerExists(issuer, tenantId)) {
            String msg = "";
            if (StringUtils.isNotBlank(issuerQualifier)) {
                msg = String.format("SAML2 Service Provider already exists with the same saml issuer name : %s, " +
                        "qualifier name : %s , and tenant Id : %d.", issuerWithoutQualifier, issuerQualifier, tenantId);
            } else {
                msg = String.format("SAML2 Service Provider already exists with the same issuer name : %s in " +
                        "tenantId = %d.", issuerWithoutQualifier, tenantId);
            }
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            throw new IdentityException(msg);
        }

        try {
            prepStmt = connection.prepareStatement(ADD_SAML_APP);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, issuer);
            prepStmt.setString(3, SAML2);
            prepStmt.setInt(6, appId);
            prepStmt.setString(7, STANDARD_APPLICATION);

            addKeyValuePair(prepStmt, ISSUER, resource.getProperty(ISSUER), issuer, tenantId, isDryRun);
            for (String assertionConsumerUrl: resource.getPropertyValues(ASSERTION_CONSUMER_URLS)) {
                addKeyValuePair(prepStmt, ASSERTION_CONSUMER_URLS, assertionConsumerUrl, issuer, tenantId,
                        isDryRun);
            }
            addKeyValuePair(prepStmt, DEFAULT_ASSERTION_CONSUMER_URL,
                    resource.getProperty(DEFAULT_ASSERTION_CONSUMER_URL), issuer, tenantId, isDryRun);
            addKeyValuePair(prepStmt, ISSUER_CERT_ALIAS, resource.getProperty(ISSUER_CERT_ALIAS), issuer, tenantId,
                    isDryRun);

            if (StringUtils.isNotEmpty(resource.getProperty(SIGNING_ALGORITHM))) {
                addKeyValuePair(prepStmt, SIGNING_ALGORITHM, resource.getProperty(SIGNING_ALGORITHM), issuer,
                        tenantId, isDryRun);
            }

            if (resource.getProperty(ASSERTION_QUERY_REQUEST_PROFILE_ENABLED) != null) {
                addKeyValuePair(prepStmt, ASSERTION_QUERY_REQUEST_PROFILE_ENABLED,
                        resource.getProperty(ASSERTION_QUERY_REQUEST_PROFILE_ENABLED), issuer, tenantId, isDryRun);
            }

            if (resource.getProperty(SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES) != null) {
                addKeyValuePair(prepStmt, SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES,
                        resource.getProperty(SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES), issuer, tenantId, isDryRun);
            }

            if (resource.getProperty(ENABLE_SAML2_ARTIFACT_BINDING) != null) {
                addKeyValuePair(prepStmt, ENABLE_SAML2_ARTIFACT_BINDING,
                        resource.getProperty(ENABLE_SAML2_ARTIFACT_BINDING), issuer, tenantId, isDryRun);
            }

            if (StringUtils.isNotEmpty(resource.getProperty(DIGEST_ALGORITHM))) {
                addKeyValuePair(prepStmt, DIGEST_ALGORITHM, resource.getProperty(DIGEST_ALGORITHM),
                        issuer, tenantId, isDryRun);
            }

            if (StringUtils.isNotEmpty(resource.getProperty(ASSERTION_ENCRYPTION_ALGORITHM))) {
                addKeyValuePair(prepStmt, ASSERTION_ENCRYPTION_ALGORITHM,
                        resource.getProperty(ASSERTION_ENCRYPTION_ALGORITHM), issuer, tenantId, isDryRun);
            }

            if (StringUtils.isNotEmpty(resource.getProperty(KEY_ENCRYPTION_ALGORITHM))) {
                addKeyValuePair(prepStmt, KEY_ENCRYPTION_ALGORITHM, resource.getProperty(KEY_ENCRYPTION_ALGORITHM),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty(DO_SINGLE_LOGOUT) != null) {
                addKeyValuePair(prepStmt, DO_SINGLE_LOGOUT, resource.getProperty(DO_SINGLE_LOGOUT).trim(),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty(NAME_ID_FORMAT) != null) {
                addKeyValuePair(prepStmt, NAME_ID_FORMAT, resource.getProperty(NAME_ID_FORMAT), issuer,
                        tenantId, isDryRun);
            }

            if (resource.getProperty(ENABLE_NAME_ID_CLAIM_URI) != null &&
                    Boolean.parseBoolean(resource.getProperty(ENABLE_NAME_ID_CLAIM_URI).trim())) {
                addKeyValuePair(prepStmt, NAME_ID_CLAIM_URI, resource.getProperty(NAME_ID_CLAIM_URI), issuer,
                        tenantId, isDryRun);
            }

            addKeyValuePair(prepStmt, LOGIN_PAGE_URL, resource.getProperty(LOGIN_PAGE_URL), issuer, tenantId,
                    isDryRun);

            if (resource.getProperty(DO_SIGN_RESPONSE) != null) {
                addKeyValuePair(prepStmt, DO_SIGN_RESPONSE, resource.getProperty(DO_SIGN_RESPONSE).trim(), issuer,
                        tenantId, isDryRun);
            }

            if (Boolean.parseBoolean(resource.getProperty(DO_SINGLE_LOGOUT).trim())) {
                addKeyValuePair(prepStmt, SLO_RESPONSE_URL, resource.getProperty(SLO_RESPONSE_URL), issuer,
                        tenantId, isDryRun);
                addKeyValuePair(prepStmt, SLO_REQUEST_URL, resource.getProperty(SLO_REQUEST_URL), issuer,
                        tenantId, isDryRun);

                if (resource.getProperty(DO_FRONT_CHANNEL_LOGOUT) != null) {
                    addKeyValuePair(prepStmt, DO_FRONT_CHANNEL_LOGOUT,
                            resource.getProperty(DO_FRONT_CHANNEL_LOGOUT).trim(), issuer, tenantId, isDryRun);
                    if (Boolean.parseBoolean(resource.getProperty(DO_FRONT_CHANNEL_LOGOUT).trim())) {
                        if (resource.getProperty(FRONT_CHANNEL_LOGOUT_BINDING) != null) {
                            addKeyValuePair(prepStmt, FRONT_CHANNEL_LOGOUT_BINDING,
                                    resource.getProperty(FRONT_CHANNEL_LOGOUT_BINDING), issuer, tenantId, isDryRun);
                        } else {
                            addKeyValuePair(prepStmt, FRONT_CHANNEL_LOGOUT_BINDING,
                                    resource.getProperty(DEFAULT_FRONT_CHANNEL_LOGOUT_BINDING), issuer, tenantId, isDryRun);
                        }
                    }
                }
            }

            if (resource.getProperty(DO_SIGN_ASSERTIONS) != null) {
                addKeyValuePair(prepStmt, DO_SIGN_ASSERTIONS, resource.getProperty(DO_SIGN_ASSERTIONS).trim(),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty(ENABLE_ECP) != null) {
                addKeyValuePair(prepStmt, ENABLE_ECP, resource.getProperty(ENABLE_ECP).trim(),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty(ATTRIBUTE_CONSUMING_SERVICE_INDEX) != null) {
                addKeyValuePair(prepStmt, ATTRIBUTE_CONSUMING_SERVICE_INDEX,
                        resource.getProperty(ATTRIBUTE_CONSUMING_SERVICE_INDEX), issuer, tenantId, isDryRun);
            } else {
                addKeyValuePair(prepStmt, ATTRIBUTE_CONSUMING_SERVICE_INDEX, "", issuer, tenantId, isDryRun);
            }

            if (resource.getProperty(REQUESTED_CLAIMS) != null) {
                addKeyValuePair(prepStmt, REQUESTED_CLAIMS, resource.getProperty(REQUESTED_CLAIMS), issuer,
                        tenantId, isDryRun);
            }

            if (resource.getProperty(REQUESTED_AUDIENCES) != null) {
                addKeyValuePair(prepStmt, REQUESTED_AUDIENCES, resource.getProperty(REQUESTED_AUDIENCES), issuer,
                        tenantId, isDryRun);
            }

            if (resource.getProperty(REQUESTED_RECIPIENTS) != null) {
                addKeyValuePair(prepStmt, REQUESTED_RECIPIENTS, resource.getProperty(REQUESTED_RECIPIENTS),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty(ENABLE_ATTRIBUTES_BY_DEFAULT) != null) {
                String enableAttrByDefault = resource.getProperty(ENABLE_ATTRIBUTES_BY_DEFAULT);
                addKeyValuePair(prepStmt, ENABLE_ATTRIBUTES_BY_DEFAULT, enableAttrByDefault, issuer, tenantId,
                        isDryRun);
            }

            if (resource.getProperty(IDP_INIT_SSO_ENABLED) != null) {
                addKeyValuePair(prepStmt, IDP_INIT_SSO_ENABLED, resource.getProperty(IDP_INIT_SSO_ENABLED).trim(),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty(IDP_INIT_SLO_ENABLED) != null) {
                addKeyValuePair(prepStmt, IDP_INIT_SLO_ENABLED, resource.getProperty(IDP_INIT_SLO_ENABLED).trim(),
                        issuer, tenantId, isDryRun);
                if (Boolean.parseBoolean(resource.getProperty(IDP_INIT_SLO_ENABLED).trim()) &&
                        resource.getProperty(IDP_INIT_SLO_RETURN_URLS) != null) {
                    addKeyValuePair(prepStmt, IDP_INIT_SLO_RETURN_URLS,
                            resource.getProperty(IDP_INIT_SLO_RETURN_URLS), issuer, tenantId, isDryRun);
                }
            }

            if (resource.getProperty(ENABLE_ENCRYPTED_ASSERTION) != null) {
                addKeyValuePair(prepStmt, ENABLE_ENCRYPTED_ASSERTION,
                        resource.getProperty(ENABLE_ENCRYPTED_ASSERTION).trim(), issuer, tenantId, isDryRun);
            }

            if (resource.getProperty(VALIDATE_SIGNATURE_IN_REQUESTS) != null) {
                addKeyValuePair(prepStmt, VALIDATE_SIGNATURE_IN_REQUESTS,
                        resource.getProperty(VALIDATE_SIGNATURE_IN_REQUESTS).trim(), issuer, tenantId, isDryRun);
            }

            if (resource.getProperty(VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE) != null) {
                addKeyValuePair(prepStmt, VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE,
                        resource.getProperty(VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE).trim(), issuer, tenantId,
                        isDryRun);
            }

            if (resource.getProperty(ISSUER_QUALIFIER) != null) {
                addKeyValuePair(prepStmt, ISSUER_QUALIFIER, resource.getProperty(ISSUER_QUALIFIER), issuer, tenantId,
                        isDryRun);
            }

            if (resource.getProperty(IDP_ENTITY_ID_ALIAS) != null) {
                addKeyValuePair(prepStmt, IDP_ENTITY_ID_ALIAS, resource.getProperty(IDP_ENTITY_ID_ALIAS), issuer,
                        tenantId, isDryRun);
            }
            prepStmt.executeBatch();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            String msg = "Error adding new service provider to the database with issuer" +
                    issuer + " , and AppID = " + appId;
            log.error(msg, e);
            throw new IdentityException(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }



    }

    private boolean isSAMLIssuerExists(String issuer, int tenantId) throws IdentityException {

        PreparedStatement prepStmt = null;
        ResultSet results = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);

        try {
            prepStmt = connection.prepareStatement(CHECK_SAML_APP_EXISTS_BY_ISSUER);
            prepStmt.setString(1, issuer);
            prepStmt.setString(2, SAML2);
            prepStmt.setInt(3, tenantId);
            prepStmt.setString(4, ISSUER);
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
        try {
            prepStmt = connection.prepareStatement(GET_SP_APP_ID_BY_ISSUER);
            prepStmt.setString(1, issuer);
            prepStmt.setInt(2, tenantId);
            prepStmt.setString(3, SAML2);
            results = prepStmt.executeQuery();
            if (results.next()) {
                log.debug(String.format("Found service provider application with ID : %d", results.getInt(1)));
                return results.getInt(1);
            }
        } catch (SQLException e) {
            String msg = "Error checking service provider from the database with issuer : " + issuer;
            throw new IdentityException(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, results, prepStmt);
        }
        return -1;
    }

    private String getIssuerWithoutQualifier(String issuerWithQualifier) {

        String issuerWithoutQualifier = StringUtils.substringBeforeLast(issuerWithQualifier,
                IdentityRegistryResources.QUALIFIER_ID);
        return issuerWithoutQualifier;
    }

    private void addKeyValuePair(PreparedStatement prepStmt, String key, String value, String issuerName, int tenantId,
                                 boolean isDryRun) throws SQLException {
        if(value == null) {
            return;
        }
        if (isDryRun) {
            reportUtil.writeMessage(String.format("%40s | %40s | %40s | %40s ", issuerName,
                    key, value, tenantId));
        } else {
            prepStmt.setString(4, key);
            prepStmt.setString(5, value);
            prepStmt.addBatch();
        }
    }
}
