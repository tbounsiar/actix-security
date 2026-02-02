//! Ant-style Path Matcher
//!
//! Provides Spring-style Ant path matching for URL patterns.
//! This is an alternative to regex-based matching, providing more intuitive
//! pattern syntax commonly used in Spring Security.
//!
//! # Pattern Syntax
//!
//! - `?` matches exactly one character
//! - `*` matches zero or more characters within a path segment
//! - `**` matches zero or more path segments
//! - `{name}` captures a named path variable
//!
//! # Examples
//!
//! ```rust
//! use actix_security_core::http::security::ant_matcher::AntMatcher;
//!
//! // Match any path under /api/
//! let matcher = AntMatcher::new("/api/**");
//! assert!(matcher.matches("/api/users"));
//! assert!(matcher.matches("/api/users/123/profile"));
//!
//! // Match single segment wildcard
//! let matcher = AntMatcher::new("/users/*/profile");
//! assert!(matcher.matches("/users/123/profile"));
//! assert!(!matcher.matches("/users/123/456/profile"));
//!
//! // Match single character
//! let matcher = AntMatcher::new("/file?.txt");
//! assert!(matcher.matches("/file1.txt"));
//! assert!(!matcher.matches("/file12.txt"));
//! ```
//!
//! # Spring Equivalent
//!
//! `org.springframework.util.AntPathMatcher`

use std::collections::HashMap;

/// Ant-style path matcher
///
/// Provides pattern matching similar to Spring's AntPathMatcher.
#[derive(Debug, Clone)]
pub struct AntMatcher {
    pattern: String,
    segments: Vec<PatternSegment>,
    case_sensitive: bool,
}

/// A segment of the pattern
#[derive(Debug, Clone, PartialEq)]
enum PatternSegment {
    /// Literal text (no wildcards)
    Literal(String),
    /// Single segment wildcard (*)
    SingleWildcard,
    /// Multi-segment wildcard (**)
    DoubleWildcard,
    /// Pattern with wildcards (*, ?)
    Pattern(String),
    /// Named path variable ({name})
    Variable(String),
}

impl AntMatcher {
    /// Create a new AntMatcher with the given pattern
    ///
    /// # Pattern Syntax
    /// - `?` matches exactly one character
    /// - `*` matches zero or more characters within a path segment
    /// - `**` matches zero or more path segments
    /// - `{name}` captures a named path variable
    ///
    /// # Example
    /// ```rust
    /// use actix_security_core::http::security::ant_matcher::AntMatcher;
    ///
    /// let matcher = AntMatcher::new("/api/**");
    /// assert!(matcher.matches("/api/users"));
    /// ```
    pub fn new(pattern: &str) -> Self {
        let segments = Self::parse_pattern(pattern);
        Self {
            pattern: pattern.to_string(),
            segments,
            case_sensitive: true,
        }
    }

    /// Create a case-insensitive matcher
    pub fn case_insensitive(mut self) -> Self {
        self.case_sensitive = false;
        self
    }

    /// Get the original pattern string
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Parse pattern into segments
    fn parse_pattern(pattern: &str) -> Vec<PatternSegment> {
        let mut segments = Vec::new();
        let trimmed = pattern.trim_start_matches('/');

        if trimmed.is_empty() {
            return vec![PatternSegment::Literal(String::new())];
        }

        for part in trimmed.split('/') {
            let segment = if part == "**" {
                PatternSegment::DoubleWildcard
            } else if part == "*" {
                PatternSegment::SingleWildcard
            } else if part.starts_with('{') && part.ends_with('}') {
                let var_name = part[1..part.len() - 1].to_string();
                PatternSegment::Variable(var_name)
            } else if part.contains('*') || part.contains('?') {
                PatternSegment::Pattern(part.to_string())
            } else {
                PatternSegment::Literal(part.to_string())
            };
            segments.push(segment);
        }

        segments
    }

    /// Check if the given path matches this pattern
    ///
    /// # Example
    /// ```rust
    /// use actix_security_core::http::security::ant_matcher::AntMatcher;
    ///
    /// let matcher = AntMatcher::new("/users/*/profile");
    /// assert!(matcher.matches("/users/123/profile"));
    /// assert!(!matcher.matches("/users/profile"));
    /// ```
    pub fn matches(&self, path: &str) -> bool {
        self.do_match(path, &mut None)
    }

    /// Check if the path matches and extract path variables
    ///
    /// # Example
    /// ```rust
    /// use actix_security_core::http::security::ant_matcher::AntMatcher;
    ///
    /// let matcher = AntMatcher::new("/users/{id}/posts/{postId}");
    /// let vars = matcher.extract_variables("/users/123/posts/456");
    ///
    /// assert!(vars.is_some());
    /// let vars = vars.unwrap();
    /// assert_eq!(vars.get("id"), Some(&"123".to_string()));
    /// assert_eq!(vars.get("postId"), Some(&"456".to_string()));
    /// ```
    pub fn extract_variables(&self, path: &str) -> Option<HashMap<String, String>> {
        let mut variables = HashMap::new();
        if self.do_match(path, &mut Some(&mut variables)) {
            Some(variables)
        } else {
            None
        }
    }

    /// Internal matching function
    fn do_match(&self, path: &str, variables: &mut Option<&mut HashMap<String, String>>) -> bool {
        let path_segments: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        self.match_segments(&self.segments, &path_segments, 0, 0, variables)
    }

    /// Recursively match pattern segments against path segments
    fn match_segments(
        &self,
        pattern_segments: &[PatternSegment],
        path_segments: &[&str],
        pattern_idx: usize,
        path_idx: usize,
        variables: &mut Option<&mut HashMap<String, String>>,
    ) -> bool {
        // Both exhausted - success
        if pattern_idx >= pattern_segments.len() && path_idx >= path_segments.len() {
            return true;
        }

        // Pattern exhausted but path remains - fail
        if pattern_idx >= pattern_segments.len() {
            return false;
        }

        let pattern_segment = &pattern_segments[pattern_idx];

        match pattern_segment {
            PatternSegment::DoubleWildcard => {
                // ** matches zero or more path segments
                // Try matching 0, 1, 2, ... path segments
                for skip in 0..=(path_segments.len() - path_idx) {
                    if self.match_segments(
                        pattern_segments,
                        path_segments,
                        pattern_idx + 1,
                        path_idx + skip,
                        variables,
                    ) {
                        return true;
                    }
                }
                false
            }

            PatternSegment::SingleWildcard | PatternSegment::Variable(_) => {
                // * or {var} matches exactly one segment
                if path_idx >= path_segments.len() {
                    return false;
                }

                // Store variable if capturing
                if let PatternSegment::Variable(name) = pattern_segment {
                    if let Some(ref mut vars) = variables {
                        vars.insert(name.clone(), path_segments[path_idx].to_string());
                    }
                }

                self.match_segments(
                    pattern_segments,
                    path_segments,
                    pattern_idx + 1,
                    path_idx + 1,
                    variables,
                )
            }

            PatternSegment::Pattern(pattern) => {
                // Pattern with wildcards
                if path_idx >= path_segments.len() {
                    return false;
                }

                if self.match_pattern(pattern, path_segments[path_idx]) {
                    self.match_segments(
                        pattern_segments,
                        path_segments,
                        pattern_idx + 1,
                        path_idx + 1,
                        variables,
                    )
                } else {
                    false
                }
            }

            PatternSegment::Literal(literal) => {
                if path_idx >= path_segments.len() {
                    // Check for empty literal (matches root)
                    return literal.is_empty()
                        && pattern_idx + 1 >= pattern_segments.len();
                }

                let path_segment = path_segments[path_idx];
                let matches = if self.case_sensitive {
                    literal == path_segment
                } else {
                    literal.eq_ignore_ascii_case(path_segment)
                };

                if matches {
                    self.match_segments(
                        pattern_segments,
                        path_segments,
                        pattern_idx + 1,
                        path_idx + 1,
                        variables,
                    )
                } else {
                    false
                }
            }
        }
    }

    /// Match a pattern segment containing * or ? against a path segment
    fn match_pattern(&self, pattern: &str, text: &str) -> bool {
        let pattern_chars: Vec<char> = pattern.chars().collect();
        let text_chars: Vec<char> = if self.case_sensitive {
            text.chars().collect()
        } else {
            text.to_lowercase().chars().collect()
        };

        let pattern_lower: Vec<char> = if self.case_sensitive {
            pattern_chars.clone()
        } else {
            pattern.to_lowercase().chars().collect()
        };

        self.match_pattern_chars(&pattern_lower, &text_chars, 0, 0)
    }

    /// Recursively match pattern characters against text characters
    fn match_pattern_chars(
        &self,
        pattern: &[char],
        text: &[char],
        p_idx: usize,
        t_idx: usize,
    ) -> bool {
        // Both exhausted - success
        if p_idx >= pattern.len() && t_idx >= text.len() {
            return true;
        }

        // Pattern exhausted but text remains - fail
        if p_idx >= pattern.len() {
            return false;
        }

        let p_char = pattern[p_idx];

        match p_char {
            '*' => {
                // * matches zero or more characters
                for skip in 0..=(text.len() - t_idx) {
                    if self.match_pattern_chars(pattern, text, p_idx + 1, t_idx + skip) {
                        return true;
                    }
                }
                false
            }
            '?' => {
                // ? matches exactly one character
                if t_idx >= text.len() {
                    return false;
                }
                self.match_pattern_chars(pattern, text, p_idx + 1, t_idx + 1)
            }
            _ => {
                // Literal character
                if t_idx >= text.len() {
                    return false;
                }
                if p_char == text[t_idx] {
                    self.match_pattern_chars(pattern, text, p_idx + 1, t_idx + 1)
                } else {
                    false
                }
            }
        }
    }
}

/// Builder for creating multiple AntMatchers with common configuration
#[derive(Debug, Clone, Default)]
pub struct AntMatcherBuilder {
    case_sensitive: bool,
}

impl AntMatcherBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            case_sensitive: true,
        }
    }

    /// Set case sensitivity (default: true)
    pub fn case_sensitive(mut self, sensitive: bool) -> Self {
        self.case_sensitive = sensitive;
        self
    }

    /// Build a matcher with the given pattern
    pub fn build(&self, pattern: &str) -> AntMatcher {
        let mut matcher = AntMatcher::new(pattern);
        if !self.case_sensitive {
            matcher = matcher.case_insensitive();
        }
        matcher
    }
}

/// Collection of AntMatchers for efficient path matching
#[derive(Debug, Clone, Default)]
pub struct AntMatchers {
    matchers: Vec<AntMatcher>,
}

impl AntMatchers {
    /// Create an empty collection
    pub fn new() -> Self {
        Self {
            matchers: Vec::new(),
        }
    }

    /// Add a pattern to the collection
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, pattern: &str) -> Self {
        self.matchers.push(AntMatcher::new(pattern));
        self
    }

    /// Add multiple patterns
    pub fn add_all(mut self, patterns: &[&str]) -> Self {
        for pattern in patterns {
            self.matchers.push(AntMatcher::new(pattern));
        }
        self
    }

    /// Check if any pattern matches the given path
    pub fn matches(&self, path: &str) -> bool {
        self.matchers.iter().any(|m| m.matches(path))
    }

    /// Get the first matching pattern, if any
    pub fn find_match(&self, path: &str) -> Option<&AntMatcher> {
        self.matchers.iter().find(|m| m.matches(path))
    }

    /// Get all matching patterns
    pub fn find_all_matches(&self, path: &str) -> Vec<&AntMatcher> {
        self.matchers.iter().filter(|m| m.matches(path)).collect()
    }

    /// Get the number of matchers
    pub fn len(&self) -> usize {
        self.matchers.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }
}

/// Extension trait for converting patterns to AntMatcher
pub trait IntoAntMatcher {
    fn into_ant_matcher(self) -> AntMatcher;
}

impl IntoAntMatcher for &str {
    fn into_ant_matcher(self) -> AntMatcher {
        AntMatcher::new(self)
    }
}

impl IntoAntMatcher for String {
    fn into_ant_matcher(self) -> AntMatcher {
        AntMatcher::new(&self)
    }
}

impl IntoAntMatcher for AntMatcher {
    fn into_ant_matcher(self) -> AntMatcher {
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_match() {
        let matcher = AntMatcher::new("/api/users");
        assert!(matcher.matches("/api/users"));
        // Trailing slashes are normalized (both patterns and paths)
        assert!(matcher.matches("/api/users/"));
        assert!(!matcher.matches("/api/user"));
        assert!(!matcher.matches("/api/users/123"));
    }

    #[test]
    fn test_single_wildcard() {
        let matcher = AntMatcher::new("/users/*/profile");
        assert!(matcher.matches("/users/123/profile"));
        assert!(matcher.matches("/users/abc/profile"));
        assert!(!matcher.matches("/users/profile"));
        assert!(!matcher.matches("/users/123/456/profile"));
    }

    #[test]
    fn test_double_wildcard() {
        let matcher = AntMatcher::new("/api/**");
        assert!(matcher.matches("/api/"));
        assert!(matcher.matches("/api/users"));
        assert!(matcher.matches("/api/users/123"));
        assert!(matcher.matches("/api/users/123/posts"));
        assert!(!matcher.matches("/other/path"));
    }

    #[test]
    fn test_double_wildcard_middle() {
        let matcher = AntMatcher::new("/api/**/edit");
        assert!(matcher.matches("/api/edit"));
        assert!(matcher.matches("/api/users/edit"));
        assert!(matcher.matches("/api/users/123/edit"));
        assert!(!matcher.matches("/api/users/123"));
    }

    #[test]
    fn test_question_mark() {
        let matcher = AntMatcher::new("/file?.txt");
        assert!(matcher.matches("/file1.txt"));
        assert!(matcher.matches("/fileA.txt"));
        assert!(!matcher.matches("/file12.txt"));
        assert!(!matcher.matches("/file.txt"));
    }

    #[test]
    fn test_pattern_wildcard() {
        let matcher = AntMatcher::new("/files/*.txt");
        assert!(matcher.matches("/files/document.txt"));
        assert!(matcher.matches("/files/test.txt"));
        assert!(!matcher.matches("/files/document.pdf"));
        assert!(!matcher.matches("/files/subdir/document.txt"));
    }

    #[test]
    fn test_variable_extraction() {
        let matcher = AntMatcher::new("/users/{id}");
        let vars = matcher.extract_variables("/users/123");
        assert!(vars.is_some());
        let vars = vars.unwrap();
        assert_eq!(vars.get("id"), Some(&"123".to_string()));
    }

    #[test]
    fn test_multiple_variables() {
        let matcher = AntMatcher::new("/users/{userId}/posts/{postId}");
        let vars = matcher.extract_variables("/users/42/posts/99");
        assert!(vars.is_some());
        let vars = vars.unwrap();
        assert_eq!(vars.get("userId"), Some(&"42".to_string()));
        assert_eq!(vars.get("postId"), Some(&"99".to_string()));
    }

    #[test]
    fn test_case_insensitive() {
        let matcher = AntMatcher::new("/Api/Users").case_insensitive();
        assert!(matcher.matches("/api/users"));
        assert!(matcher.matches("/API/USERS"));
        assert!(matcher.matches("/Api/Users"));
    }

    #[test]
    fn test_root_path() {
        let matcher = AntMatcher::new("/");
        assert!(matcher.matches("/"));
    }

    #[test]
    fn test_complex_pattern() {
        let matcher = AntMatcher::new("/api/v*/users/**/profile");
        assert!(matcher.matches("/api/v1/users/123/profile"));
        assert!(matcher.matches("/api/v2/users/123/posts/456/profile"));
        assert!(!matcher.matches("/api/users/123/profile"));
    }

    #[test]
    fn test_ant_matchers_collection() {
        let matchers = AntMatchers::new()
            .add("/api/**")
            .add("/public/**")
            .add("/health");

        assert!(matchers.matches("/api/users"));
        assert!(matchers.matches("/public/images/logo.png"));
        assert!(matchers.matches("/health"));
        assert!(!matchers.matches("/private/data"));
    }

    #[test]
    fn test_ant_matchers_find() {
        let matchers = AntMatchers::new()
            .add("/api/**")
            .add("/admin/**");

        let found = matchers.find_match("/api/users");
        assert!(found.is_some());
        assert_eq!(found.unwrap().pattern(), "/api/**");
    }

    #[test]
    fn test_builder() {
        let builder = AntMatcherBuilder::new().case_sensitive(false);
        let matcher = builder.build("/API/USERS");
        assert!(matcher.matches("/api/users"));
    }

    #[test]
    fn test_into_ant_matcher() {
        let m1: AntMatcher = "/api/**".into_ant_matcher();
        let m2: AntMatcher = String::from("/users/*").into_ant_matcher();

        assert!(m1.matches("/api/test"));
        assert!(m2.matches("/users/123"));
    }

    #[test]
    fn test_trailing_slash() {
        let matcher = AntMatcher::new("/api/users/");
        // Trailing slashes are normalized - both paths match
        assert!(matcher.matches("/api/users")); // No trailing slash
        assert!(matcher.matches("/api/users/")); // With trailing slash
    }

    #[test]
    fn test_mixed_wildcards() {
        let matcher = AntMatcher::new("/api/*/items/**");
        assert!(matcher.matches("/api/v1/items/1"));
        assert!(matcher.matches("/api/v1/items/1/2/3"));
        assert!(matcher.matches("/api/v2/items/"));
        assert!(!matcher.matches("/api/v1/v2/items/1"));
    }

    #[test]
    fn test_pattern_segment_equality() {
        assert_eq!(PatternSegment::SingleWildcard, PatternSegment::SingleWildcard);
        assert_eq!(PatternSegment::DoubleWildcard, PatternSegment::DoubleWildcard);
        assert_eq!(
            PatternSegment::Literal("test".to_string()),
            PatternSegment::Literal("test".to_string())
        );
    }
}
