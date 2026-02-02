//! Security expression parser.
//!
//! Parses Spring Security-like expressions into an AST.

use std::fmt;
use std::iter::Peekable;
use std::str::Chars;

use super::ast::{BinaryOp, Expression, UnaryOp};

/// Error type for expression parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Unexpected end of input
    UnexpectedEof,
    /// Unexpected character
    UnexpectedChar(char),
    /// Unexpected token
    UnexpectedToken(String),
    /// Unclosed parenthesis
    UnclosedParen,
    /// Unclosed string
    UnclosedString,
    /// Empty expression
    EmptyExpression,
    /// Invalid function call
    InvalidFunction(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnexpectedEof => write!(f, "unexpected end of expression"),
            ParseError::UnexpectedChar(c) => write!(f, "unexpected character: '{}'", c),
            ParseError::UnexpectedToken(t) => write!(f, "unexpected token: '{}'", t),
            ParseError::UnclosedParen => write!(f, "unclosed parenthesis"),
            ParseError::UnclosedString => write!(f, "unclosed string literal"),
            ParseError::EmptyExpression => write!(f, "empty expression"),
            ParseError::InvalidFunction(name) => write!(f, "invalid function: '{}'", name),
        }
    }
}

impl std::error::Error for ParseError {}

/// Token types for the lexer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// Identifier (function name, keyword)
    Ident(String),
    /// String literal
    String(String),
    /// Left parenthesis
    LParen,
    /// Right parenthesis
    RParen,
    /// Comma
    Comma,
    /// AND operator
    And,
    /// OR operator
    Or,
    /// NOT operator
    Not,
    /// Boolean true
    True,
    /// Boolean false
    False,
}

/// A parsed security expression.
///
/// # Example
/// ```ignore
/// use actix_security_core::http::security::expression::SecurityExpression;
///
/// let expr = SecurityExpression::parse("hasRole('ADMIN') OR hasAuthority('write')")?;
/// let result = expr.evaluate(&user);
/// ```
#[derive(Debug, Clone)]
pub struct SecurityExpression {
    /// The original expression string
    source: String,
    /// The parsed AST
    ast: Expression,
}

impl SecurityExpression {
    /// Parses a security expression string.
    ///
    /// # Arguments
    /// * `expr` - The expression string to parse
    ///
    /// # Returns
    /// A parsed `SecurityExpression` or a `ParseError`
    ///
    /// # Example
    /// ```ignore
    /// let expr = SecurityExpression::parse("hasRole('ADMIN')")?;
    /// ```
    pub fn parse(expr: &str) -> Result<Self, ParseError> {
        let tokens = tokenize(expr)?;
        if tokens.is_empty() {
            return Err(ParseError::EmptyExpression);
        }

        let ast = Parser::new(tokens).parse()?;

        Ok(SecurityExpression {
            source: expr.to_string(),
            ast,
        })
    }

    /// Returns the original expression string.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns a reference to the parsed AST.
    pub fn ast(&self) -> &Expression {
        &self.ast
    }

    /// Consumes self and returns the AST.
    pub fn into_ast(self) -> Expression {
        self.ast
    }
}

/// Tokenizes an expression string into tokens.
fn tokenize(expr: &str) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let mut chars = expr.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            // Whitespace - skip
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }

            // Parentheses
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }

            // Comma
            ',' => {
                chars.next();
                tokens.push(Token::Comma);
            }

            // String literals (single or double quotes)
            '\'' | '"' => {
                tokens.push(parse_string(&mut chars)?);
            }

            // Operators
            '&' => {
                chars.next();
                if chars.peek() == Some(&'&') {
                    chars.next();
                    tokens.push(Token::And);
                } else {
                    return Err(ParseError::UnexpectedChar('&'));
                }
            }
            '|' => {
                chars.next();
                if chars.peek() == Some(&'|') {
                    chars.next();
                    tokens.push(Token::Or);
                } else {
                    return Err(ParseError::UnexpectedChar('|'));
                }
            }
            '!' => {
                chars.next();
                tokens.push(Token::Not);
            }

            // Identifiers and keywords
            'a'..='z' | 'A'..='Z' | '_' => {
                tokens.push(parse_identifier(&mut chars));
            }

            // Unknown character
            _ => {
                return Err(ParseError::UnexpectedChar(c));
            }
        }
    }

    Ok(tokens)
}

/// Parses a string literal.
fn parse_string(chars: &mut Peekable<Chars>) -> Result<Token, ParseError> {
    let quote = chars.next().unwrap(); // ' or "
    let mut value = String::new();

    loop {
        match chars.next() {
            Some(c) if c == quote => {
                return Ok(Token::String(value));
            }
            Some('\\') => {
                // Escape sequence
                if let Some(escaped) = chars.next() {
                    value.push(escaped);
                } else {
                    return Err(ParseError::UnclosedString);
                }
            }
            Some(c) => {
                value.push(c);
            }
            None => {
                return Err(ParseError::UnclosedString);
            }
        }
    }
}

/// Parses an identifier or keyword.
fn parse_identifier(chars: &mut Peekable<Chars>) -> Token {
    let mut ident = String::new();

    while let Some(&c) = chars.peek() {
        if c.is_alphanumeric() || c == '_' {
            ident.push(c);
            chars.next();
        } else {
            break;
        }
    }

    // Check for keywords
    match ident.to_lowercase().as_str() {
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "true" => Token::True,
        "false" => Token::False,
        _ => Token::Ident(ident),
    }
}

/// Recursive descent parser for security expressions.
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0 }
    }

    fn parse(&mut self) -> Result<Expression, ParseError> {
        let expr = self.parse_or()?;

        if self.pos < self.tokens.len() {
            return Err(ParseError::UnexpectedToken(format!(
                "{:?}",
                self.tokens[self.pos]
            )));
        }

        Ok(expr)
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.pos);
        self.pos += 1;
        token
    }

    /// Parse OR expressions (lowest precedence)
    fn parse_or(&mut self) -> Result<Expression, ParseError> {
        let mut left = self.parse_and()?;

        while matches!(self.peek(), Some(Token::Or)) {
            self.advance();
            let right = self.parse_and()?;
            left = Expression::Binary {
                left: Box::new(left),
                op: BinaryOp::Or,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// Parse AND expressions (higher precedence than OR)
    fn parse_and(&mut self) -> Result<Expression, ParseError> {
        let mut left = self.parse_unary()?;

        while matches!(self.peek(), Some(Token::And)) {
            self.advance();
            let right = self.parse_unary()?;
            left = Expression::Binary {
                left: Box::new(left),
                op: BinaryOp::And,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// Parse unary expressions (NOT)
    fn parse_unary(&mut self) -> Result<Expression, ParseError> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.advance();
            let expr = self.parse_unary()?;
            return Ok(Expression::Unary {
                op: UnaryOp::Not,
                expr: Box::new(expr),
            });
        }

        self.parse_primary()
    }

    /// Parse primary expressions (functions, booleans, groups)
    fn parse_primary(&mut self) -> Result<Expression, ParseError> {
        match self.peek().cloned() {
            Some(Token::True) => {
                self.advance();
                Ok(Expression::Boolean(true))
            }
            Some(Token::False) => {
                self.advance();
                Ok(Expression::Boolean(false))
            }
            Some(Token::LParen) => {
                self.advance();
                let expr = self.parse_or()?;
                if !matches!(self.peek(), Some(Token::RParen)) {
                    return Err(ParseError::UnclosedParen);
                }
                self.advance();
                Ok(Expression::Group(Box::new(expr)))
            }
            Some(Token::Ident(name)) => {
                self.advance();
                self.parse_function_call(name)
            }
            Some(token) => Err(ParseError::UnexpectedToken(format!("{:?}", token))),
            None => Err(ParseError::UnexpectedEof),
        }
    }

    /// Parse function call arguments
    fn parse_function_call(&mut self, name: String) -> Result<Expression, ParseError> {
        // Expect opening parenthesis
        if !matches!(self.peek(), Some(Token::LParen)) {
            return Err(ParseError::InvalidFunction(name));
        }
        self.advance();

        let mut args = Vec::new();

        // Parse arguments
        if !matches!(self.peek(), Some(Token::RParen)) {
            loop {
                match self.peek().cloned() {
                    Some(Token::String(s)) => {
                        self.advance();
                        args.push(s);
                    }
                    Some(Token::Ident(s)) => {
                        // Allow unquoted identifiers as arguments
                        self.advance();
                        args.push(s);
                    }
                    Some(token) => {
                        return Err(ParseError::UnexpectedToken(format!("{:?}", token)));
                    }
                    None => {
                        return Err(ParseError::UnclosedParen);
                    }
                }

                // Check for comma or closing paren
                match self.peek() {
                    Some(Token::Comma) => {
                        self.advance();
                    }
                    Some(Token::RParen) => break,
                    Some(token) => {
                        return Err(ParseError::UnexpectedToken(format!("{:?}", token)));
                    }
                    None => {
                        return Err(ParseError::UnclosedParen);
                    }
                }
            }
        }

        // Expect closing parenthesis
        if !matches!(self.peek(), Some(Token::RParen)) {
            return Err(ParseError::UnclosedParen);
        }
        self.advance();

        Ok(Expression::Function { name, args })
    }
}
