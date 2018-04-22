package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.sql.DataSource;
import java.beans.PropertyVetoException;
import java.io.Serializable;

@EnableGlobalMethodSecurity
@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @Bean
    public MyRepository defaultMyRepository() {
        return new MyRepository();
    }

    @Order(Ordered.LOWEST_PRECEDENCE - 9)
    @Configuration
    public static class ActuatorSecurity extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests().anyRequest().permitAll();
        }
    }

    @Bean
    public AclCache defaultAclCache() {
        return new AclCache() {
            @Override
            public void evictFromCache(Serializable pk) {

            }

            @Override
            public void evictFromCache(ObjectIdentity objectIdentity) {

            }

            @Override
            public MutableAcl getFromCache(ObjectIdentity objectIdentity) {
                return null;
            }

            @Override
            public MutableAcl getFromCache(Serializable pk) {
                return null;
            }

            @Override
            public void putInCache(MutableAcl acl) {

            }

            @Override
            public void clearCache() {

            }
        };
    }

    @Bean(name = "expressionHandler")
    @ConditionalOnMissingBean(name = "expressionHandler")
    public MethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler(final PermissionEvaluator permissionEvaluator) {
        final DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setPermissionEvaluator(permissionEvaluator);

        return expressionHandler;
    }

    @Bean(name = { "defaultPermissionEvaluator", "permissionEvaluator" })
    @ConditionalOnMissingBean(name = { "defaultPermissionEvaluator" })
    public PermissionEvaluator defaultPermissionEvaluator(final AclService aclService, final ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy)
                    throws PropertyVetoException {
        final AclPermissionEvaluator permissionEvaluator = new AclPermissionEvaluator(aclService);
        permissionEvaluator.setObjectIdentityRetrievalStrategy(objectIdentityRetrievalStrategy);

        return permissionEvaluator;
    }

    @Bean(name = { "defaultObjectIdentityRetrievalStrategy", "objectIdentityRetrievalStrategy" })
    @ConditionalOnMissingBean(name = { "objectIdentityRetrievalStrategy" })
    public ObjectIdentityRetrievalStrategy defaultObjectIdentityRetrievalStrategy() {
        return new ObjectIdentityRetrievalStrategyImpl();
    }

    @Bean(name = { "defaultAclService", "aclService" })
    @ConditionalOnMissingBean(name = { "aclService" })
    public AclService defaultAclService(final DataSource dataSource, AclCache aclCache) throws PropertyVetoException {
        return new JdbcMutableAclService(dataSource,
                                         new BasicLookupStrategy(dataSource, aclCache, new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("TEST")),
                                                                 new ConsoleAuditLogger()), aclCache);
    }

    class MyRepository {
        @PersistenceContext(name = "entityManagerFactory")
        private EntityManager entityManager;

        public EntityManager getEntityManager() {
            return entityManager;
        }

        public void setEntityManager(EntityManager entityManager) {
            this.entityManager = entityManager;
        }
    }
}
