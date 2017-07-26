# pentaho-authentication-filter

This bundle helps implement authentication filtering in Pentaho by being chained into the Spring Security Filter Chain.

# Build

```
mvn package
```

# Deploy

* Stop Pentaho Server;

* Copy the lib into pentaho webapp classpath

```BASH 
cp ./target/authentication-filter-TRUNK-SNAPSHOT.jar /<INSTALL_DIR>/pentaho-server/tomcat/webapps/pentaho/WEB-INF/lib/
```

* Insert the `</bean>` into `system/applicationContext-spring-security.xml`

```xml
<bean id="authenticationIPFilter" class="com.oncase.security.filter.authentication.AuthenticationIPFilter">
</bean>
```


* To configure the list of roles, insert inside the bean (** authenticationIPFilter **)

```xml
  <property name="debug" value="true" />
  <property name="adminRole" value="Administrator" />
  <property name="rules">
   <map>
      <entry> 
        <key>
          <value>Power User</value> 
        </key>
        <list>                  
          <value>0:0:0:0:0:0:0:1</value>
          <value>127.0.0.1</value>
        </list>
      </entry>
      <entry> 
        <key>
          <value>Business Analyst</value> 
        </key>
        <list>                  
          <value>NOTHING</value>
        </list>
      </entry>
    </map> 
  </property>
```

* Insert the new bean ID into the chain (**authenticationIPFilter**)

```xml
  <bean id="filterChainProxy" class="org.springframework.security.web.FilterChainProxy">
    <constructor-arg>
      <util:list>
        <!--
           You can safely remove the first pattern starting with /content/dashboards/print, if you're not using
           Enterprise Dashboards or not allowing printing of Dashboards,
        -->
        <sec:filter-chain pattern="/api/repos/dashboards/print" filters="securityContextHolderAwareRequestFilter,httpSessionPentahoSessionContextIntegrationFilter,httpSessionContextIntegrationFilter,preAuthenticatedSecurityFilter,httpSessionReuseDetectionFilter,logoutFilter,authenticationProcessingFilter,basicProcessingFilter,requestParameterProcessingFilter,authenticationIPFilter,anonymousProcessingFilter,sessionMgmtFilter,exceptionTranslationFilter,filterInvocationInterceptor" />
        <sec:filter-chain pattern="/webservices/**" filters="securityContextHolderAwareRequestFilterForWS,httpSessionPentahoSessionContextIntegrationFilter,httpSessionContextIntegrationFilter,basicProcessingFilter,anonymousProcessingFilter,sessionMgmtFilter,exceptionTranslationFilterForWS,filterInvocationInterceptorForWS" />
        <sec:filter-chain pattern="/api/repos/**" filters="securityContextHolderAwareRequestFilterForWS,httpSessionPentahoSessionContextIntegrationFilter,httpSessionContextIntegrationFilter,basicProcessingFilter,requestParameterProcessingFilter,authenticationIPFilter,anonymousProcessingFilter,sessionMgmtFilter,exceptionTranslationFilterForWS,filterInvocationInterceptorForWS,preFlightFilter" />
        <sec:filter-chain pattern="/api/**" filters="securityContextHolderAwareRequestFilterForWS,httpSessionPentahoSessionContextIntegrationFilter,httpSessionContextIntegrationFilter,basicProcessingFilter,requestParameterProcessingFilter,authenticationIPFilter,anonymousProcessingFilter,sessionMgmtFilter,exceptionTranslationFilterForWS,filterInvocationInterceptorForWS" />
        <sec:filter-chain pattern="/plugin/reporting/api/jobs/**" filters="securityContextHolderAwareRequestFilterForWS,httpSessionPentahoSessionContextIntegrationFilter,httpSessionContextIntegrationFilter,basicProcessingFilter,requestParameterProcessingFilter,authenticationIPFilter,anonymousProcessingFilter,sessionMgmtFilter,exceptionTranslationFilterForWS,filterInvocationInterceptorForWS,preFlightFilter" />
        <sec:filter-chain pattern="/plugin/**" filters="securityContextHolderAwareRequestFilterForWS,httpSessionPentahoSessionContextIntegrationFilter,httpSessionContextIntegrationFilter,basicProcessingFilter,requestParameterProcessingFilter,authenticationIPFilter,anonymousProcessingFilter,sessionMgmtFilter,exceptionTranslationFilterForWS,filterInvocationInterceptorForWS" />
        <sec:filter-chain pattern="/**" filters="securityContextHolderAwareRequestFilter,httpSessionPentahoSessionContextIntegrationFilter,httpSessionContextIntegrationFilter,httpSessionReuseDetectionFilter,logoutFilter,authenticationProcessingFilter,basicProcessingFilter,requestParameterProcessingFilter,authenticationIPFilter,anonymousProcessingFilter,sessionMgmtFilter,exceptionTranslationFilter,filterInvocationInterceptor" />
      </util:list>
    </constructor-arg>
  </bean>
```


* Start Pentaho Server;

# TODO

This is only an example so far. What we should do is to:
 
 - Externalize a config file with a map<String, String[]> with roles and ip addresses to allow accesses to - in order to restrict access from certain companies/Roles;
 - Attempt to programmatically inject this filter into the existing chains.

Keep in mind

> The main goal of this project is to restrict the access of certain Roles (Companies that access the platform) to specific known ip addresses/masks.
