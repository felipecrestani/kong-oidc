local M = {}

local function shouldIgnoreRequest(patterns)
  if (patterns) then
    for _, pattern in ipairs(patterns) do
      local isMatching = not (string.find(ngx.var.uri, pattern) == nil)
      if (isMatching) then return true end
    end
  end
  return false
end

local function headerPresent(headerList)
  if headerList and headerList ~= '' then
    for _, header in ipairs(headerList) do
      return ngx.req.get_headers()[header] and ngx.req.get_headers()[header] ~= ''
    end    
  end
  return false
end

local function cookiePresent(cookie_attr_list)
  if cookie_attr_list and cookie_attr_list ~= '' then
    local cookie = ngx.req.get_headers()['Cookie']
    return cookie and cookie ~= '' and string.find(cookie, cookie_attr .. "=",1,true)
  end
  return false  
end

function M.shouldProcessRequest(config)
  return not (headerPresent(config.bypass_header) or cookiePresent(config.bypass_cookie)) and (not shouldIgnoreRequest(config.filters))
end

function M.isAuthBootstrapRequest(config)
  if (config.auth_bootstrap_path and config.auth_bootstrap_path ~= '') then
    local found_at = string.find(ngx.var.uri, config.auth_bootstrap_path,1,true) 
    return found_at and found_at == 1
  else
    return false
  end
end

function M.isOAuthCodeRequest()
  ngx.log(ngx.DEBUG, "oauth check on url: " .. ngx.var.request_uri)
  return string.find(ngx.var.request_uri,"?code=") 
end

return M
