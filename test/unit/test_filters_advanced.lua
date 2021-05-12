local filter = require("kong.plugins.oidc.filter")
local lu = require("luaunit")

TestFilter = require("test.unit.mockable_case"):extend()

function TestFilter:setUp()
  TestFilter.super:setUp()
  _G.ngx = {
    var = {
      uri = ""
    },
    req = {
      get_headers = function() return {} end
    }
  }
end

function TestFilter:tearDown()
  TestFilter.super:tearDown()
end


local config =  {
  filters = {  "^/auth$","^/auth[^%w_%-%.~]","^/arc$","^/arc[^%w_%-%.~]","^/projects/%d+/zeppelin[^%w_%-%.~]","^/projects/%d+/zeppelin$"}
}

function TestFilter:testIgnoreRequestWhenUriIsAuth()
  ngx.var.uri = "/auth"
  lu.assertFalse(filter.shouldProcessRequest(config))

  ngx.var.uri = "/auth/"
  lu.assertFalse(filter.shouldProcessRequest(config))
end

function TestFilter:testIgnoreRequestWhenUriIsArc()
  ngx.var.uri = "/arc"
  lu.assertFalse(filter.shouldProcessRequest(config))

  ngx.var.uri = "/arc/"
  lu.assertFalse(filter.shouldProcessRequest(config))
end

function TestFilter:testProcessRequestWhichAreAllowed()
  ngx.var.uri = "/not_auth"
  assert(filter.shouldProcessRequest(config) == true)
end

function TestFilter:testIgnoreRequestBeingIdenticalToFilter()
  ngx.var.uri = "/arc"
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testIgnoreRequestStartingWithFilterFollowedBySlash()
  ngx.var.uri = "/arc/"
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testIgnoreRequestStartingWithFilterFollowedByPaths()
  ngx.var.uri = "/arc/de/triomphe"
  lu.assertFalse(filter.shouldProcessRequest(config) )

end

function TestFilter:testIgnoreRequestStartingWithFilterFollowedByQuestionmark()
  ngx.var.uri = "/arc?"
  lu.assertFalse(filter.shouldProcessRequest(config) )

  ngx.var.uri = "/arc?de=triomphe"
  lu.assertFalse(filter.shouldProcessRequest(config) )

end

function TestFilter:testIgnoreRequestStartingWithFilterFollowedByQuestionmark()
  ngx.var.uri = "/arc?"
  lu.assertFalse(filter.shouldProcessRequest(config) )

  ngx.var.uri = "/arc?de=triomphe"
  lu.assertFalse(filter.shouldProcessRequest(config) )

end

function TestFilter:testPrefixNotAtTheStart()
  ngx.var.uri = "/process_this/arc"
  lu.assertTrue(filter.shouldProcessRequest(config) )

  ngx.var.uri = "/process_this/arc/de/triomphe"
  lu.assertTrue(filter.shouldProcessRequest(config) )

  ngx.var.uri = "/process_this/architecture"
  lu.assertTrue(filter.shouldProcessRequest(config) )

end

function TestFilter:testLowercaseLetterAfterPrefix()
  ngx.var.uri = "/architecture"
  lu.assertTrue(filter.shouldProcessRequest(config) )
end

function TestFilter:testUppercaseLetterLetterAfterPrefix()
  ngx.var.uri = "/archITACTURE"
  lu.assertTrue(filter.shouldProcessRequest(config) )
end

function TestFilter:testDigitAfterPrefix()
  ngx.var.uri = "/arc123"
  lu.assertTrue(filter.shouldProcessRequest(config) )
end

function TestFilter:testHyphenAfterPrefix()
  ngx.var.uri = "/arc-123"
  lu.assertTrue(filter.shouldProcessRequest(config) )
end

function TestFilter:testPeriodAfterPrefix()
  ngx.var.uri = "/arc.123"
  lu.assertTrue(filter.shouldProcessRequest(config) )
end

function TestFilter:testUnderscoreAfterPrefix()
  ngx.var.uri = "/arc_123"
  lu.assertTrue(filter.shouldProcessRequest(config) )
end

function TestFilter:testTildeAfterPrefix()
  ngx.var.uri = "/arc~123"
  lu.assertTrue(filter.shouldProcessRequest(config) )
end

function TestFilter:testBypassWhenCookie()
  config.bypass_cookie = "Auth-Token"
  ngx.req.get_headers = function () 
     return { Cookie = 'Auth-Token=bla;'} 
  end
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testBypassWhenHeader()
  config.bypass_header = "XAuthorization"
  ngx.req.get_headers = function () 
     return { XAuthorization = 'blue'} 
  end
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testBypassBothConfiguredCookieProvided()
  config.bypass_header = "XAuthorization"
  config.bypass_cookie = "Auth-Token"
  ngx.req.get_headers = function () 
      return { Cookie = 'Auth-Token=bla;'} 
  end
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testBypassBothConfiguredHeaderProvided()
  config.bypass_header = "XAuthorization"
  config.bypass_cookie = "Auth-Token"
  ngx.req.get_headers = function () 
      return { XAuthorization = 'blue'} 
  end
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testBypassBothConfiguredBothProvided()
  config.bypass_header = "XAuthorization"
  config.bypass_cookie = "Auth-Token"
  ngx.req.get_headers = function () 
      return { XAuthorization = 'blue', Cookie = "Auth-Token=blue"} 
  end
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testBypassCookieListWhenSingleCookieProvided()
  config.bypass_cookie_list = {"Auth-Token","Other-Token"}
  ngx.req.get_headers = function () 
      return { Cookie = "Auth-Token=blue"} 
  end
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testBypassCookieListWhenBothCookiesProvided()
  config.bypass_cookie_list = {"Auth-Token","Other-Token"}
  ngx.req.get_headers = function () 
      return { Cookie = "Other-Token=xyz;Auth-Token=blue;"} 
  end
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testNoBypassWithCookieList()
  config.bypass_cookie_list = {"Auth-Token","Other-Token"}
  ngx.req.get_headers = function () 
      return { Cookie = "Zambas=true;"} 
  end
  lu.assertTrue(filter.shouldProcessRequest(config) )
end

function TestFilter:testBypassHeaderListWhenSingleHeaderProvided()
  config.bypass_header_list = {"zambas","X-Authorization"}
  ngx.req.get_headers = function () 
      local headers = {}
      headers['X-Authorization'] = 'fakeToken'
      return headers  
  end
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testBypassHeaderListWhenBothHeadersProvided()
  config.bypass_header_list = {"zambas","XAuthorization"}
  ngx.req.get_headers = function () 
    local headers = {}
    headers['X-Authorization'] = 'fakeToken'
    headers['zambas'] = 'otherValue'
    return headers 
  end
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testNoBypassWithHeaderList()
  config.bypass_header_list = {"xyz","xpto"}
  ngx.req.get_headers = function () 
    local headers = {}
    headers['X-Authorization'] = 'fakeToken'
    return headers
  end
  lu.assertTrue(filter.shouldProcessRequest(config) )
end

function TestFilter:testBypassHeaderListWithNoCookieMatch()
  config.bypass_header_list = {"xyz","xpto"}
  config.bypass_cookie_list = {"Auth-Token","Other-Token"}
  
  ngx.req.get_headers = function () 
      return { xyz = 'blue', Cookie = "zambas=true"} 
  end
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

function TestFilter:testBypassCookieListWithNoHeaderMatch()
  config.bypass_header_list = {"xyz","xpto"}
  config.bypass_cookie_list = {"Auth-Token","Other-Token"}
  
  ngx.req.get_headers = function () 
      return { zambas = 'blue', Cookie = "Auth-Token=123456;xxxxxx=true"} 
  end
  lu.assertFalse(filter.shouldProcessRequest(config) )
end

lu.run()