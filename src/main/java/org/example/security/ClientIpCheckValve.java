package org.example.security;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.concurrent.ConcurrentHashMap;

public class ClientIpCheckValve extends ValveBase {
  private volatile DataSource dataSource;
  private String dataSourceJndiName;
  private String allowedIpQuery;
  private static ConcurrentHashMap<String, String> allowedIpList = new ConcurrentHashMap<>();

  private static final Log log = LogFactory.getLog(ClientIpCheckValve.class);

  public void setDataSourceJndiName(String jndiName) {
    if (jndiName != null && !jndiName.trim().isEmpty()) {
      this.dataSourceJndiName = jndiName.trim();
    } else {
      this.dataSourceJndiName = null;
    }
  }

  public void setAllowedIpQuery(String allowedIpQuery) {
    if (allowedIpQuery != null && !allowedIpQuery.trim().isEmpty()) {
      this.allowedIpQuery = allowedIpQuery.trim();
    } else {
      this.allowedIpQuery = null;
    }
  }

  @Override
  public void invoke(Request request, Response response) throws IOException, ServletException {
    String clientIp = request.getRemoteAddr();
    log.info("Request received from ip=" + clientIp);
    if (!isAllowed(clientIp)) {
      log.warn("Blocking ip=" + clientIp);
      response.sendError(HttpServletResponse.SC_FORBIDDEN, "IP not allowed: " + clientIp);
      return;
    }

    log.info("Request from ip=" + clientIp + " allowed");
    getNext().invoke(request, response);
  }

  private boolean isAllowed(String ip) {
    if (allowedIpQuery == null || allowedIpQuery.isEmpty()) {
      log.error("No allowedIpQuery configured for ClientIpCheckValve");
      return false;
    }

    try (Connection conn = getDataSource().getConnection();
         PreparedStatement ps = conn.prepareStatement(allowedIpQuery)) {
      ps.setString(1, ip);
      log.info("Executing ip lookup for ip=" + ip);
      try (ResultSet rs = ps.executeQuery()) {
        boolean allowed = rs.next();
        log.info("checkUserIp returned allowed=" + allowed + " for ip=" + ip);
        return allowed;
      }
    } catch (SQLException e) {
      log.error("Failed to query for IP = " + ip, e);
      return false;
    }
  }

  private DataSource getDataSource() {
    if (dataSource == null) {
      synchronized (this) {
        if (dataSource == null) {
          dataSource = lookupDataSource();
        }
      }
    }
    return dataSource;
  }

  private DataSource lookupDataSource() {
    if (dataSourceJndiName == null || dataSourceJndiName.trim().isEmpty()) {
      throw new IllegalStateException("dataSourceJndiName must be configured for ClientIpCheckValve");
    }

    try {
      Context context = new InitialContext();
      return (DataSource) context.lookup(dataSourceJndiName);
    } catch (NamingException e) {
      throw new IllegalStateException("Unable to look up DataSource via JNDI: " + dataSourceJndiName, e);
    }
  }
}
