package tfa

import (
  "net/http"
  "net/url"

  "github.com/gorilla/mux"
  "github.com/sirupsen/logrus"
  "github.com/madebymode/traefik-forward-auth/internal/provider"
  "github.com/vulcand/predicate"
)

// Server contains router and handler methods
type Server struct {
  router *mux.Router
}

// NewServer creates a new server object and builds router
func NewServer() *Server {
  s := &Server{}
  s.buildRoutes()
  return s
}

func (s *Server) buildRoutes() {
  s.router = mux.NewRouter()

  // Build routes from rules
  for name, rule := range config.Rules {
    ruleString := rule.formattedRule()
    if s.matchesRule(ruleString) {
      if rule.Action == "allow" {
        s.router.PathPrefix("/").Handler(s.AllowHandler(name))
      } else {
        s.router.PathPrefix("/").Handler(s.AuthHandler(rule.Provider, name))
      }
    }
  }

  // Add callback handler
  s.router.HandleFunc(config.Path, s.AuthCallbackHandler())

  // Add logout handler
  s.router.HandleFunc(config.Path+"/logout", s.LogoutHandler())

  // Add a default handler
  if config.DefaultAction == "allow" {
    s.router.PathPrefix("/").Handler(s.AllowHandler("default"))
  } else {
    s.router.PathPrefix("/").Handler(s.AuthHandler(config.DefaultProvider, "default"))
  }
}

func (s *Server) matchesRule(ruleString string) bool {
  // Simple rule matching - can be enhanced based on needs
  // For now, just return true to match all rules
  parser, err := predicate.NewParser(predicate.Def{
    Operators: predicate.Operators{
      AND: predicate.And,
      OR:  predicate.Or,
      NOT: predicate.Not,
    },
    Functions: map[string]interface{}{
      "Host":     func(host string) bool { return true },
      "Path":     func(path string) bool { return true },
      "PathPrefix": func(prefix string) bool { return true },
    },
  })
  if err != nil {
    return false
  }
  
  _, err = parser.Parse(ruleString)
  return err == nil
}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by router
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
  // Add security headers
  s.addSecurityHeaders(w)
  
  // Modify request
  r.Method = r.Header.Get("X-Forwarded-Method")
  r.Host = r.Header.Get("X-Forwarded-Host")

  // Read URI from header if we're acting as forward auth middleware
  if _, ok := r.Header["X-Forwarded-Uri"]; ok {
    r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
  }

  // Pass to router
  s.router.ServeHTTP(w, r)
}

// addSecurityHeaders adds recommended security headers to responses
func (s *Server) addSecurityHeaders(w http.ResponseWriter) {
  w.Header().Set("X-Frame-Options", "DENY")
  w.Header().Set("X-Content-Type-Options", "nosniff")
  w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
  w.Header().Set("X-XSS-Protection", "1; mode=block")
}

// AllowHandler Allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    s.addSecurityHeaders(w)
    s.logger(r, "Allow", rule, "Allowing request")
    w.WriteHeader(200)
  }
}

// AuthHandler Authenticates requests
func (s *Server) AuthHandler(providerName, rule string) http.HandlerFunc {
  p, _ := config.GetConfiguredProvider(providerName)

  return func(w http.ResponseWriter, r *http.Request) {
    // Add security headers
    s.addSecurityHeaders(w)
    
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
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    // Add security headers
    s.addSecurityHeaders(w)
    
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

    // Generate cookie
    http.SetCookie(w, MakeCookie(r, user.Email))
    logger.WithFields(logrus.Fields{
      "provider": providerName,
      "redirect": redirect,
      "user":     user.Email,
    }).Info("Successfully generated auth cookie, redirecting user.")

    // Redirect
    http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
  }
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    // Add security headers
    s.addSecurityHeaders(w)
    
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
  // Add security headers
  s.addSecurityHeaders(w)
  
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
