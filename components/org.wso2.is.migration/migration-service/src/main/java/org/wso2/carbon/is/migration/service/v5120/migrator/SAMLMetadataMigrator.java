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
            moveServiceProvidersToRegistry(registry, tenantId, isDryRun, tenantDomain);
            if (!isDryRun) {
                removeAllServiceProvidersFromRegistry(registry, tenantId);
            }
        } catch (RegistryException e) {
            log.error(Constant.MIGRATION_LOG + "Error while getting data from the registry.", e);
        } catch (IdentityException e) {
            log.error(Constant.MIGRATION_LOG + "Error while initializing the registry for : " + tenantDomain, e);
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
        String issuer = resource.getProperty("Issuer");
        String issuerQualifier = resource.getProperty("SpQualifier");
        int appId = getServiceProviderAppId(issuer, tenantId);

        if (appId == -1) {
            if (log.isDebugEnabled()) {
                if (StringUtils.isNotBlank(issuerQualifier)) {
                    log.debug("Cannot Find a ServiceProvider with the issuer Name " + issuer + " and tenantId "
                            + tenantId);
                } else {
                    log.debug("SAML2 Service Provider already exists with the same issuer name "
                            + issuer);
                }
            }
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);

        PreparedStatement prepStmt = null;

        if (issuer == null ||
                StringUtils.isBlank(issuer)) {
            throw new IdentityException("Issuer cannot be found in the provided arguments.");
        }

        // If an issuer qualifier value is specified, it is appended to the end of the issuer value.
        if (StringUtils.isNotBlank(issuerQualifier)) {
            issuer = getIssuerWithQualifier(issuer, issuerQualifier);
        }

        if (isServiceProviderExists(issuer, tenantId)) {
            if (log.isDebugEnabled()) {
                if (StringUtils.isNotBlank(issuerQualifier)) {
                    log.debug("SAML2 Service Provider already exists with the same issuer name "
                            + getIssuerWithoutQualifier(issuer) + " and qualifier name "
                            + issuerQualifier);
                } else {
                    log.debug("SAML2 Service Provider already exists with the same issuer name "
                            + issuer);
                }
            }
            return;
        }

        try {
            prepStmt = connection.prepareStatement(ADD_SAML_APP);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, issuer);
            prepStmt.setString(3, SAML2);
            prepStmt.setInt(6, appId);
            prepStmt.setString(7, STANDARD_APPLICATION);

            addKeyValuePair(prepStmt, "Issuer", resource.getProperty("Issuer"), issuer, tenantId, isDryRun);
            for (String assertionConsumerUrl: resource.getPropertyValues("SAMLSSOAssertionConsumerURLs")) {
                addKeyValuePair(prepStmt, "SAMLSSOAssertionConsumerURLs", assertionConsumerUrl, issuer, tenantId,
                        isDryRun);
            }
            addKeyValuePair(prepStmt, "DefaultSAMLSSOAssertionConsumerURL",
                    resource.getProperty("DefaultSAMLSSOAssertionConsumerURL"), issuer, tenantId, isDryRun);
            addKeyValuePair(prepStmt, "IssuerCertAlias", resource.getProperty("IssuerCertAlias"), issuer, tenantId,
                    isDryRun);

            if (StringUtils.isNotEmpty(resource.getProperty("signingAlgorithm"))) {
                addKeyValuePair(prepStmt, "signingAlgorithm", resource.getProperty("signingAlgorithm"), issuer,
                        tenantId, isDryRun);
            }

            if (resource.getProperty("AssertionQueryRequestProfileEnabled") != null) {
                addKeyValuePair(prepStmt, "AssertionQueryRequestProfileEnabled",
                        resource.getProperty("AssertionQueryRequestProfileEnabled"), issuer, tenantId, isDryRun);
            }

            if (resource.getProperty("SupportedAssertionQueryRequestTypes") != null) {
                addKeyValuePair(prepStmt, "SupportedAssertionQueryRequestTypes",
                        resource.getProperty("SupportedAssertionQueryRequestTypes"), issuer, tenantId, isDryRun);
            }

            if (resource.getProperty("EnableSAML2ArtifactBinding") != null) {
                addKeyValuePair(prepStmt, "EnableSAML2ArtifactBinding",
                        resource.getProperty("EnableSAML2ArtifactBinding"), issuer, tenantId, isDryRun);
            }

            if (StringUtils.isNotEmpty(resource.getProperty("digestAlgorithm"))) {
                addKeyValuePair(prepStmt, "digestAlgorithm", resource.getProperty("digestAlgorithm"),
                        issuer, tenantId, isDryRun);
            }

            if (StringUtils.isNotEmpty(resource.getProperty("assertionEncryptionAlgorithm"))) {
                addKeyValuePair(prepStmt, "assertionEncryptionAlgorithm",
                        resource.getProperty("assertionEncryptionAlgorithm"), issuer, tenantId, isDryRun);
            }

            if (StringUtils.isNotEmpty(resource.getProperty("keyEncryptionAlgorithm"))) {
                addKeyValuePair(prepStmt, "keyEncryptionAlgorithm", resource.getProperty("keyEncryptionAlgorithm"),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty("doSingleLogout") != null) {
                addKeyValuePair(prepStmt, "doSingleLogout", resource.getProperty("doSingleLogout").trim(),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty("NameIDFormat") != null) {
                addKeyValuePair(prepStmt, "NameIDFormat", resource.getProperty("NameIDFormat"), issuer,
                        tenantId, isDryRun);
            }

            if (resource.getProperty("EnableNameIDClaimUri") != null &&
                    Boolean.valueOf(resource.getProperty("EnableNameIDClaimUri").trim())) {
                addKeyValuePair(prepStmt, "NameIDClaimUri", resource.getProperty("NameIDClaimUri"), issuer,
                        tenantId, isDryRun);
            }

            addKeyValuePair(prepStmt, "loginPageURL", resource.getProperty("loginPageURL"), issuer, tenantId,
                    isDryRun);

            if (resource.getProperty("doSignResponse") != null) {
                addKeyValuePair(prepStmt, "doSignResponse", resource.getProperty("doSignResponse").trim(), issuer,
                        tenantId, isDryRun);
            }

            if (Boolean.valueOf(resource.getProperty("doSingleLogout").trim())) {
                addKeyValuePair(prepStmt, "sloResponseURL", resource.getProperty("sloResponseURL"), issuer,
                        tenantId, isDryRun);
                addKeyValuePair(prepStmt, "sloRequestURL", resource.getProperty("sloRequestURL"), issuer,
                        tenantId, isDryRun);

                if (resource.getProperty("doFrontChannelLogout") != null) {
                    addKeyValuePair(prepStmt, "doFrontChannelLogout",
                            resource.getProperty("doFrontChannelLogout").trim(), issuer, tenantId, isDryRun);
                    if (Boolean.valueOf(resource.getProperty("doFrontChannelLogout").trim())) {
                        if (resource.getProperty("frontChannelLogoutBinding") != null) {
                            addKeyValuePair(prepStmt, "frontChannelLogoutBinding",
                                    resource.getProperty("frontChannelLogoutBinding"), issuer, tenantId, isDryRun);
                        } else {
                            addKeyValuePair(prepStmt, "frontChannelLogoutBinding",
                                    resource.getProperty("HTTPRedirectBinding"), issuer, tenantId, isDryRun);
                        }
                    }
                }
            }

            if (resource.getProperty("doSignAssertions") != null) {
                addKeyValuePair(prepStmt, "doSignAssertions", resource.getProperty("doSignAssertions").trim(),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty("EnableSAMLECP") != null) {
                addKeyValuePair(prepStmt, "EnableSAMLECP", resource.getProperty("EnableSAMLECP").trim(),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty("AttributeConsumingServiceIndex") != null) {
                addKeyValuePair(prepStmt, "AttributeConsumingServiceIndex",
                        resource.getProperty("AttributeConsumingServiceIndex"), issuer, tenantId, isDryRun);
            } else {
                addKeyValuePair(prepStmt, "AttributeConsumingServiceIndex", "", issuer, tenantId, isDryRun);
            }

            if (resource.getProperty("RequestedClaims") != null) {
                addKeyValuePair(prepStmt, "RequestedClaims", resource.getProperty("RequestedClaims"), issuer,
                        tenantId, isDryRun);
            }

            if (resource.getProperty("RequestedAudiences") != null) {
                addKeyValuePair(prepStmt, "RequestedAudiences", resource.getProperty("RequestedAudiences"), issuer,
                        tenantId, isDryRun);
            }

            if (resource.getProperty("RequestedRecipients") != null) {
                addKeyValuePair(prepStmt, "RequestedRecipients", resource.getProperty("RequestedRecipients"),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty("EnableAttributesByDefault") != null) {
                String enableAttrByDefault = resource.getProperty("EnableAttributesByDefault");
                addKeyValuePair(prepStmt, "EnableAttributesByDefault", enableAttrByDefault, issuer, tenantId,
                        isDryRun);
            }

            if (resource.getProperty("IdPInitSSOEnabled") != null) {
                addKeyValuePair(prepStmt, "IdPInitSSOEnabled", resource.getProperty("IdPInitSSOEnabled").trim(),
                        issuer, tenantId, isDryRun);
            }

            if (resource.getProperty("IdPInitSLOEnabled") != null) {
                addKeyValuePair(prepStmt, "IdPInitSLOEnabled", resource.getProperty("IdPInitSLOEnabled").trim(),
                        issuer, tenantId, isDryRun);
                if (Boolean.valueOf(resource.getProperty("IdPInitSLOEnabled").trim()) &&
                        resource.getProperty("IdPInitiatedSLOReturnToURLs") != null) {
                    addKeyValuePair(prepStmt, "IdPInitiatedSLOReturnToURLs",
                            resource.getProperty("IdPInitiatedSLOReturnToURLs"), issuer, tenantId, isDryRun);
                }
            }

            if (resource.getProperty("doEnableEncryptedAssertion") != null) {
                addKeyValuePair(prepStmt, "doEnableEncryptedAssertion",
                        resource.getProperty("doEnableEncryptedAssertion").trim(), issuer, tenantId, isDryRun);
            }

            if (resource.getProperty("doValidateSignatureInRequests") != null) {
                addKeyValuePair(prepStmt, "doValidateSignatureInRequests",
                        resource.getProperty("doValidateSignatureInRequests").trim(), issuer, tenantId, isDryRun);
            }

            if (resource.getProperty("doValidateSignatureInArtifactResolve") != null) {
                addKeyValuePair(prepStmt, "doValidateSignatureInArtifactResolve",
                        resource.getProperty("doValidateSignatureInArtifactResolve").trim(), issuer, tenantId,
                        isDryRun);
            }

            if (resource.getProperty("SpQualifier") != null) {
                addKeyValuePair(prepStmt, "SpQualifier", resource.getProperty("SpQualifier"), issuer, tenantId,
                        isDryRun);
            }

            if (resource.getProperty("IdPEntityIDAlias") != null) {
                addKeyValuePair(prepStmt, "IdPEntityIDAlias", resource.getProperty("IdPEntityIDAlias"), issuer,
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
                String msg = "My Results = " + results.toString();
                log.error(msg);
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

    private void addKeyValuePair(PreparedStatement prepStmt, String key, String value, String issuerName, int tenantId,
                                 boolean isDryRun) throws SQLException {
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
