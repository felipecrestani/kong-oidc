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

local function headerPresent(header)
  if header and header ~= '' then
    return ngx.req.get_headers()[header] and ngx.req.get_headers()[header] ~= ''
  end
  return false
end

local function cookiePresent(cookie_attr)
  if cookie_attr and cookie_attr ~= '' then
    local cookie = ngx.req.get_headers()['Cookie']
    return cookie and cookie ~= '' and string.find(cookie, cookie_attr .. "=",1,true)
  end
  return false  
end


local function hasCookieOnList(cookie_list)
  if cookie_list and cookie_list ~= '' and ngx.req.get_headers() then
      local cookies = ngx.req.get_headers()['Cookie']
      if cookies and cookies ~= '' then
        for _, cookie in ipairs(cookie_list) do
          local found = string.find(cookies, cookie .. "=",1,true)
          if(found) then
            return 
          end
        end
      end
  end
  return false
end

local function hasHeaderOnList(header_list)
  if header_list and header_list ~= '' and ngx.req.get_headers() then
        for _, header in ipairs(header_list) do
          local found = ngx.req.get_headers()[header] and ngx.req.get_headers()[header] ~= ''
          if(found) then
            return 
          end
        end
  end
  return false
end

function M.shouldProcessRequest(config)
  return not (headerPresent(config.bypass_header) or cookiePresent(config.bypass_cookie) or hasCookieOnList(config.bypass_cookie_list) or hasHeaderOnList(config.bypass_header_list) ) and (not shouldIgnoreRequest(config.filters))
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
