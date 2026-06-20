package tfa

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/madebymode/traefik-forward-auth/internal/provider"
	"github.com/sirupsen/logrus"
	"github.com/traefik/traefik/v3/pkg/rules"
)

func hostMatchesRedirectDomain(host, domain string) bool {
	host = strings.ToLower(host)
	domain = strings.ToLower(strings.TrimPrefix(domain, "."))
	if host == domain {
		return true
	}

	return strings.HasSuffix(host, "."+domain)
}

// Server contains muxer and handler methods
type Server struct {
	routes         []route
	defaultHandler http.Handler
}

type route struct {
	matcher requestMatcher
	handler http.Handler
}

type requestMatcher func(*http.Request) bool

// NewServer creates a new server object and builds muxer
func NewServer() *Server {
	s := &Server{}
	s.buildRoutes()
	return s
}

func (s *Server) buildRoutes() {
	parser, err := rules.NewParser([]string{
		"ClientIP",
		"Method",
		"Host",
		"HostRegexp",
		"Path",
		"PathRegexp",
		"PathPrefix",
		"Header",
		"HeaderRegexp",
		"Query",
		"QueryRegexp",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Let's build a muxer
	for name, rule := range config.Rules {
		matchRule := rule.formattedRule()
		matcher, err := parseRule(parser, matchRule)
		if err != nil {
			log.Fatal(err)
		}

		if rule.Action == "allow" {
			s.routes = append(s.routes, route{matcher: matcher, handler: s.AllowHandler(name)})
		} else {
			s.routes = append(s.routes, route{matcher: matcher, handler: s.AuthHandler(rule.Provider, name)})
		}
	}

	// Add callback handler
	matcher, err := parseRule(parser, pathRule(config.Path))
	if err != nil {
		log.Fatal(err)
	}
	s.routes = append(s.routes, route{matcher: matcher, handler: s.AuthCallbackHandler()})

	// Add logout handler
	matcher, err = parseRule(parser, pathRule(config.Path+"/logout"))
	if err != nil {
		log.Fatal(err)
	}
	s.routes = append(s.routes, route{matcher: matcher, handler: s.LogoutHandler()})

	// Add a default handler
	if config.DefaultAction == "allow" {
		s.defaultHandler = s.AllowHandler("default")
	} else {
		s.defaultHandler = s.AuthHandler(config.DefaultProvider, "default")
	}
}

func pathRule(path string) string {
	return "Path(`" + path + "`)"
}

func parseRule(parser interface {
	Parse(string) (interface{}, error)
}, rule string) (requestMatcher, error) {
	parsed, err := parser.Parse(rule)
	if err != nil {
		return nil, fmt.Errorf("parsing rule %s: %w", rule, err)
	}

	buildTree, ok := parsed.(rules.TreeBuilder)
	if !ok {
		return nil, fmt.Errorf("building rule tree for %s", rule)
	}

	return compileRule(buildTree())
}

func compileRule(tree *rules.Tree) (requestMatcher, error) {
	switch tree.Matcher {
	case "and":
		left, err := compileRule(tree.RuleLeft)
		if err != nil {
			return nil, err
		}
		right, err := compileRule(tree.RuleRight)
		if err != nil {
			return nil, err
		}
		return func(r *http.Request) bool { return left(r) && right(r) }, nil
	case "or":
		left, err := compileRule(tree.RuleLeft)
		if err != nil {
			return nil, err
		}
		right, err := compileRule(tree.RuleRight)
		if err != nil {
			return nil, err
		}
		return func(r *http.Request) bool { return left(r) || right(r) }, nil
	default:
		matcher, err := compileMatcher(tree.Matcher, tree.Value)
		if err != nil {
			return nil, err
		}
		if tree.Not {
			return func(r *http.Request) bool { return !matcher(r) }, nil
		}
		return matcher, nil
	}
}

func compileMatcher(name string, values []string) (requestMatcher, error) {
	switch name {
	case "ClientIP":
		return clientIPMatcher(values)
	case "Method":
		if err := expectMatcherArgs(name, values, 1); err != nil {
			return nil, err
		}
		method := strings.ToUpper(values[0])
		return func(r *http.Request) bool { return r.Method == method }, nil
	case "Host":
		if err := expectMatcherArgs(name, values, 1); err != nil {
			return nil, err
		}
		host := strings.ToLower(values[0])
		if !isASCII(host) {
			return nil, fmt.Errorf("invalid value %q for Host matcher, non-ASCII characters are not allowed", host)
		}
		return func(r *http.Request) bool { return domainMatchHostExpression(canonicalHost(r.Host), host) }, nil
	case "HostRegexp":
		if err := expectMatcherArgs(name, values, 1); err != nil {
			return nil, err
		}
		re, err := regexp.Compile(values[0])
		if err != nil {
			return nil, fmt.Errorf("compiling HostRegexp matcher: %w", err)
		}
		return func(r *http.Request) bool { return re.MatchString(canonicalHost(r.Host)) }, nil
	case "Path":
		if err := expectMatcherArgs(name, values, 1); err != nil {
			return nil, err
		}
		path := values[0]
		if !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("path %q does not start with a '/'", path)
		}
		return func(r *http.Request) bool { return r.URL.Path == path }, nil
	case "PathRegexp":
		if err := expectMatcherArgs(name, values, 1); err != nil {
			return nil, err
		}
		re, err := regexp.Compile(values[0])
		if err != nil {
			return nil, fmt.Errorf("compiling PathRegexp matcher: %w", err)
		}
		return func(r *http.Request) bool { return re.MatchString(r.URL.Path) }, nil
	case "PathPrefix":
		if err := expectMatcherArgs(name, values, 1); err != nil {
			return nil, err
		}
		prefix := values[0]
		if !strings.HasPrefix(prefix, "/") {
			return nil, fmt.Errorf("path %q does not start with a '/'", prefix)
		}
		return func(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, prefix) }, nil
	case "Header":
		if err := expectMatcherArgs(name, values, 2); err != nil {
			return nil, err
		}
		key, value := http.CanonicalHeaderKey(values[0]), values[1]
		return func(r *http.Request) bool {
			for _, got := range r.Header.Values(key) {
				if got == value {
					return true
				}
			}
			return false
		}, nil
	case "HeaderRegexp":
		if err := expectMatcherArgs(name, values, 2); err != nil {
			return nil, err
		}
		key := http.CanonicalHeaderKey(values[0])
		re, err := regexp.Compile(values[1])
		if err != nil {
			return nil, fmt.Errorf("compiling HeaderRegexp matcher: %w", err)
		}
		return func(r *http.Request) bool {
			for _, got := range r.Header.Values(key) {
				if re.MatchString(got) {
					return true
				}
			}
			return false
		}, nil
	case "Query":
		if err := expectMatcherArgs(name, values, 1, 2); err != nil {
			return nil, err
		}
		key := values[0]
		value := ""
		if len(values) == 2 {
			value = values[1]
		}
		return func(r *http.Request) bool {
			for _, got := range r.URL.Query()[key] {
				if got == value {
					return true
				}
			}
			return false
		}, nil
	case "QueryRegexp":
		if err := expectMatcherArgs(name, values, 1, 2); err != nil {
			return nil, err
		}
		key := values[0]
		pattern := ""
		if len(values) == 2 {
			pattern = values[1]
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compiling QueryRegexp matcher: %w", err)
		}
		return func(r *http.Request) bool {
			for _, got := range r.URL.Query()[key] {
				if re.MatchString(got) {
					return true
				}
			}
			return false
		}, nil
	default:
		return nil, fmt.Errorf("unsupported matcher %s", name)
	}
}

func expectMatcherArgs(name string, values []string, valid ...int) error {
	for _, n := range valid {
		if len(values) == n {
			return nil
		}
	}
	return fmt.Errorf("unexpected number of parameters for %s matcher; got %d, expected one of %v", name, len(values), valid)
}

func clientIPMatcher(values []string) (requestMatcher, error) {
	if err := expectMatcherArgs("ClientIP", values, 1); err != nil {
		return nil, err
	}

	prefix, err := netip.ParsePrefix(values[0])
	if err != nil {
		addr, addrErr := netip.ParseAddr(values[0])
		if addrErr != nil {
			return nil, fmt.Errorf("parsing ClientIP matcher: %w", err)
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	return func(r *http.Request) bool {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		addr, err := netip.ParseAddr(host)
		return err == nil && prefix.Contains(addr)
	}, nil
}

func canonicalHost(host string) string {
	if strings.Contains(host, ":") {
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
	}
	return strings.ToLower(strings.TrimSpace(host))
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

func domainMatchHostExpression(domain, hostExpr string) bool {
	if strings.HasPrefix(hostExpr, "*") {
		labels := strings.Split(domain, ".")
		if len(labels) == 0 {
			return false
		}
		labels[0] = "*"
		return strings.EqualFold(hostExpr, strings.Join(labels, "."))
	}

	if strings.EqualFold(domain, hostExpr) {
		return true
	}
	if strings.HasSuffix(hostExpr, ".") && strings.EqualFold(domain, strings.TrimSuffix(hostExpr, ".")) {
		return true
	}
	if strings.HasSuffix(domain, ".") && strings.EqualFold(strings.TrimSuffix(domain, "."), hostExpr) {
		return true
	}
	return false
}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by mux
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")

	// Read URI from header if we're acting as forward auth middleware
	if _, ok := r.Header["X-Forwarded-Uri"]; ok {
		r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
	}

	for _, route := range s.routes {
		if route.matcher(r) {
			route.handler.ServeHTTP(w, r)
			return
		}
	}

	s.defaultHandler.ServeHTTP(w, r)
}

// AllowHandler Allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow", rule, "Allowing request")
		w.WriteHeader(200)
	}
}

// AuthHandler Authenticates requests
func (s *Server) AuthHandler(providerName, rule string) http.HandlerFunc {
	p, _ := config.GetConfiguredProvider(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Auth", rule, "Authenticating request")

		// Get auth cookie
		c, err := r.Cookie(config.CookieName)
		if err != nil {
			s.authRedirect(logger, w, r, p)
			return
		}

		// Validate cookie
		email, err := ValidateCookie(r, c)
		if err != nil {
			if err.Error() == "Cookie has expired" {
				logger.Info("Cookie has expired")
				s.authRedirect(logger, w, r, p)
			} else {
				logger.WithField("error", err).Warn("Invalid cookie")
				http.Error(w, "Not authorized", 401)
			}
			return
		}

		// Validate user
		valid := ValidateEmail(email, rule)
		if !valid {
			logger.WithField("email", email).Warn("Invalid email")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Valid request
		logger.Debug("Allowing valid request")
		w.Header().Set("X-Forwarded-User", email)
		w.WriteHeader(200)
	}
}

// AuthCallbackHandler Handles auth callback request
func sanitizeLocalRedirect(target string) (string, error) {
	normalized := strings.ReplaceAll(target, "\\", "/")
	u, err := url.Parse(normalized)
	if err != nil {
		return "", err
	}

	// Only allow local absolute-path redirects
	if u.Hostname() == "" {
		if !strings.HasPrefix(u.Path, "/") {
			return "", url.InvalidHostError(u.Host)
		}
		return u.String(), nil
	}

	if u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", url.InvalidHostError(u.Host)
	}

	for _, domain := range config.RedirectDomains {
		if hostMatchesRedirectDomain(u.Hostname(), domain) {
			return u.String(), nil
		}
	}

	return "", url.InvalidHostError(u.Host)
}

func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "AuthCallback", "default", "Handling callback")

		// Check state
		state := r.URL.Query().Get("state")
		if err := ValidateState(state); err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
			}).Warn("Error validating state")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Check for CSRF cookie
		c, err := FindCSRFCookie(r, state)
		if err != nil {
			logger.Info("Missing csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate CSRF cookie against state
		valid, providerName, redirect, err := ValidateCSRFCookie(c, state)
		if !valid {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
			}).Warn("Error validating csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Get provider
		p, err := config.GetConfiguredProvider(providerName)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
				"provider":    providerName,
			}).Warn("Invalid provider in csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r, c))

		// Exchange code for token
		token, err := p.ExchangeCode(redirectUri(r), r.URL.Query().Get("code"))
		if err != nil {
			logger.WithField("error", err).Error("Code exchange failed with provider")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Get user
		user, err := p.GetUser(token)
		if err != nil {
			logger.WithField("error", err).Error("Error getting user")
			http.Error(w, "Service unavailable", 503)
			return
		}

		safeRedirect, err := sanitizeLocalRedirect(redirect)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error":    err,
				"redirect": redirect,
			}).Warn("Invalid redirect target")
			http.Error(w, "Invalid redirect", 400)
			return
		}

		// Generate cookie
		http.SetCookie(w, MakeCookie(r, user.Email))
		logger.WithFields(logrus.Fields{
			"provider": providerName,
			"redirect": safeRedirect,
			"user":     user.Email,
		}).Info("Successfully generated auth cookie, redirecting user.")

		// Redirect
		http.Redirect(w, r, safeRedirect, http.StatusTemporaryRedirect)
	}
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear cookie
		http.SetCookie(w, ClearCookie(r))

		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info("Logged out user")

		if config.LogoutRedirect != "" {
			http.Redirect(w, r, config.LogoutRedirect, http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "You have been logged out", 401)
		}
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider) {
	// Error indicates no cookie, generate nonce
	err, nonce := Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	csrf := MakeCSRFCookie(r, nonce)
	http.SetCookie(w, csrf)

	if !config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	loginURL := p.GetLoginURL(redirectUri(r), MakeState(r, p, nonce))
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
}

func (s *Server) logger(r *http.Request, handler, rule, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"handler":   handler,
		"rule":      rule,
		"method":    r.Header.Get("X-Forwarded-Method"),
		"proto":     r.Header.Get("X-Forwarded-Proto"),
		"host":      r.Header.Get("X-Forwarded-Host"),
		"uri":       r.Header.Get("X-Forwarded-Uri"),
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"cookies": r.Cookies(),
	}).Debug(msg)

	return logger
}
