return {
  no_consumer = true,
  fields = {
    client_id = { type = "string", required = true },
    client_secret = { type = "string", required = true },
    discovery = { type = "string", required = true, default = "https://.well-known/openid-configuration" },
    introspection_endpoint = { type = "string", required = false },
    timeout = { type = "number", required = false },
    introspection_endpoint_auth_method = { type = "string", required = false },
    bearer_only = { type = "string", required = true, default = "no" },
    realm = { type = "string", required = true, default = "kong" },
    redirect_uri_path = { type = "string" },
    redirect_uri_scheme = { type = "string" },
    redirect_uri = { type = "string" },
    scope = { type = "string", required = true, default = "openid" },
    response_type = { type = "string", required = true, default = "code" },
    ssl_verify = { type = "string", required = true, default = "no" },
    inject_user = { type = "string", required = false, default = "yes" },
    inject_access_token = { type = "string", required = false, default = "yes" },
    inject_id_token = { type = "string", required = false, default = "yes" },
    ignore_nonce_validation = { type = "string", required = false, default = "no" },
    token_endpoint_auth_method = { type = "string", required = true, default = "client_secret_post" },
    session_secret = { type = "string", required = false },
    recovery_page_path = { type = "string" },
    logout_path = { type = "string", required = false, default = '/logout' },
    redirect_after_logout_uri = { type = "string", required = false, default = '/' },
    auth_bootstrap_path = { type = "string" , required = false},
    refresh_session_interval = { type = "number" , required = false},
    
    bypass_header = { type = "string", required = false },
    bypass_header_list = { type = "string", required = false },
    
    bypass_cookie = { type = "string", required = false },
    bypass_cookie_list = { type = "string", required = false },
    
    filters = { type = "string" }
  }
}
