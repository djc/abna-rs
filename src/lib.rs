//! Client library for ABN Amro online banking
//!
//! This library provides automated retrieval of mutations (transactions) from the ABN Amro
//! banking platform. It handles authentication with the bank's API and fetches transaction
//! history for specified accounts.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! let mut session = abna::Session::new("NL12ABNA0123456789".to_string()).await?;
//! session.login(1234, "12345").await?;
//!
//! let mutations = session.mutations("NL12ABNA0123456789", None).await?;
//! for mutation in &mutations.mutations {
//!     println!("{:?}", mutation.mutation);
//! }
//! # Ok(())
//! # }
//! ```

use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use aws_lc_rs::rsa::{Pkcs1PublicEncryptingKey, PublicKeyComponents};
use chrono::NaiveDateTime;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// A session for interacting with the ABN Amro banking API
///
/// This struct maintains a connection to the ABN Amro API, including cookie-based session
/// state. Create a new session with [`Session::new()`], authenticate with [`Session::login()`],
/// and retrieve transaction data with [`Session::mutations()`].
pub struct Session {
    iban: String,
    client: reqwest::Client,
}

impl Session {
    /// Creates a new session for the specified IBAN
    ///
    /// This initializes an HTTP client with cookie storage enabled for maintaining session state
    /// across requests. The session is not authenticated until [`Session::login()`] is called.
    pub async fn new(iban: String) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_STR));
        Ok(Session {
            iban,
            client: reqwest::Client::builder()
                .cookie_store(true)
                .default_headers(headers)
                .build()?,
        })
    }

    /// Authenticates the session with ABN Amro using card number and token
    ///
    /// This performs a challenge-response authentication flow with RSA encryption. The
    /// session must be successfully logged in before calling [`Session::mutations()`].
    ///
    /// # Arguments
    ///
    /// * `card` - the card number associated with the account (typically 3 digits)
    /// * `token` - the authentication token (PIN or soft token code)
    ///
    /// # Errors
    ///
    /// Reasons this could error include:
    ///
    /// - The IBAN format is invalid
    /// - The network request fails
    /// - Authentication fails (incorrect credentials)
    /// - The cryptographic operations fail
    pub async fn login(&mut self, card: u16, token: &str) -> anyhow::Result<()> {
        let login = Login {
            access_tool_usage: "SOFTTOKEN",
            account_number: u32::from_str(&self.iban[8..])?,
            app_id: "SIMPLE_BANKING",
            card_number: card,
        };

        self.client.get(START).send().await?;
        let response = self
            .client
            .get(format!("{BASE}/session/loginchallenge"))
            .query(&login)
            .send()
            .await?;

        let challenge = response.json::<Challenge>().await?;
        let response = challenge.response(login, token)?;

        let mut headers = HeaderMap::new();
        headers.insert(
            SERVICE_VERSION_HEADER,
            HeaderValue::from_static(SERVICE_VERSION),
        );

        let login_response = self
            .client
            .put(format!("{BASE}/session/loginresponse"))
            .headers(headers)
            .json(&response)
            .send()
            .await?;

        if !login_response.status().is_success() {
            let error = login_response.json::<ErrorResponse>().await?;
            anyhow::bail!("login failed: {error:?}");
        }

        Ok(())
    }

    /// Retrieves a list of mutations (transactions) for the specified account
    ///
    /// Returns transaction history with support for pagination. The session must be
    /// authenticated with [`Session::login()`] before calling this method.
    ///
    /// # Arguments
    ///
    /// * `iban` - the IBAN of the account to retrieve mutations for
    /// * `last_mutation_key` - optional key for pagination. Pass `None` to get the most
    ///   recent transactions, or use the `last_mutation_key` from a previous response to
    ///   fetch older transactions.
    ///
    ///
    /// # Errors
    ///
    /// Reasons this could error include:
    ///
    /// - The network request fails
    /// - The API returns an error response
    /// - The response cannot be parsed
    pub async fn mutations(
        &self,
        iban: &str,
        last_mutation_key: Option<&str>,
    ) -> anyhow::Result<MutationsList> {
        let params = MutationsParams {
            account_number: &self.iban,
            include_actions: "EXTENDED",
            last_mutation_key,
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            SERVICE_VERSION_HEADER,
            HeaderValue::from_static(SERVICE_VERSION),
        );

        let response = self
            .client
            .get(format!("{BASE}/mutations/{iban}"))
            .headers(headers)
            .query(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.json::<ErrorResponse>().await?;
            anyhow::bail!("mutations request failed: {error:?}");
        }

        let json = response.text().await?;
        match serde_json::from_str::<MutationsResponse>(&json) {
            Ok(rsp) => Ok(rsp.mutations_list),
            Err(error) => {
                println!("{:#?}", Value::from_str(&json)?);
                anyhow::bail!("failed to decode mutations: {error:?}");
            }
        }
    }
}

/// Response wrapper for the mutations API endpoint
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationsResponse {
    /// Mutations and associated metadata
    pub mutations_list: MutationsList,
}

/// A list of mutations with pagination metadata
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationsList {
    /// Key for fetching the next page of mutations
    ///
    /// Pass this to [`Session::mutations()`] to retrieve older transactions.
    /// `None` indicates there are no more mutations to fetch.
    pub last_mutation_key: Option<String>,
    /// Indicates whether cached data should be cleared
    pub clear_cache_indicator: bool,
    /// The list of mutations (transactions) in this response
    pub mutations: Vec<Mutation>,
}

/// A wrapper for a single mutation (transaction)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mutation {
    /// The actual transaction data.
    pub mutation: MutationData,
}

/// Details of a bank transaction (mutation)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationData {
    /// Transaction amount (positive for credits, negative for debits)
    pub amount: f64,
    /// Name of the counterparty (sender or recipient)
    pub counter_account_name: String,
    /// Account number of the counterparty
    pub counter_account_number: String,
    /// ISO currency code (like "EUR")
    pub currency_iso_code: String,
    /// Description of the transaction, potentially split across multiple lines
    pub description_lines: Vec<String>,
    /// Date and time when the transaction occurred
    ///
    /// This appears to be in the Europe/Amsterdam timezone.
    #[serde(deserialize_with = "transaction_timestamp")]
    pub transaction_timestamp: NaiveDateTime,
}

fn transaction_timestamp<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<NaiveDateTime, D::Error> {
    let s = <&str>::deserialize(deserializer)?;
    NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%S%3f").map_err(serde::de::Error::custom)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MutationsParams<'a> {
    account_number: &'a str,
    include_actions: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_mutation_key: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Login {
    access_tool_usage: &'static str,
    account_number: u32,
    app_id: &'static str,
    card_number: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRequest {
    access_tool_usage: &'static str,
    account_number: u32,
    app_id: &'static str,
    card_number: u16,
    response: String,
    challenge_handle: String,
    challenge_device_details: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Challenge {
    login_challenge: LoginChallenge,
}

impl Challenge {
    fn response(self, login: Login, token: &str) -> anyhow::Result<LoginRequest> {
        let obj = decode(&self.login_challenge.challenge)?;

        let mut out = BTreeMap::new();
        out.insert(1u8, vec![49u8]);
        out.insert(2, obj.get(&2).unwrap().clone());
        out.insert(3, obj.get(&3).unwrap().clone());
        out.insert(8, self.login_challenge.user_id.as_bytes().to_vec());
        out.insert(9, token.as_bytes().to_vec());
        let encoded = encode(out);

        let public_key = PublicKeyComponents {
            n: obj.get(&4).unwrap().as_slice(),
            e: obj.get(&5).unwrap().as_slice(),
        }
        .try_into()
        .map_err(|e| anyhow::anyhow!("failed to create RSA key: {e:?}"))?;

        let pkcs1_key = Pkcs1PublicEncryptingKey::new(public_key)
            .map_err(|e| anyhow::anyhow!("failed to create PKCS1 key: {e:?}"))?;

        let mut encrypted = vec![0u8; pkcs1_key.ciphertext_size()];
        pkcs1_key
            .encrypt(&encoded, &mut encrypted)
            .map_err(|e| anyhow::anyhow!("RSA encryption failed: {e:?}"))?;

        Ok(LoginRequest {
            access_tool_usage: login.access_tool_usage,
            account_number: login.account_number,
            app_id: login.app_id,
            card_number: login.card_number,
            response: hex::encode(&encrypted),
            challenge_handle: self.login_challenge.challenge_handle,
            challenge_device_details: self.login_challenge.challenge_device_details,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginChallenge {
    challenge: String,
    user_id: String,
    challenge_handle: String,
    challenge_device_details: String,
}

fn decode(challenge: &str) -> anyhow::Result<HashMap<u8, Vec<u8>>> {
    let bytes = hex::decode(challenge).map_err(|e| anyhow::anyhow!("hex decode error: {e}"))?;
    let mut res = HashMap::new();
    let mut cur = 0;

    while cur < bytes.len() {
        let key = bytes[cur];
        let size = ((bytes[cur + 1] as usize) << 8) + (bytes[cur + 2] as usize);
        let value = bytes[cur + 3..cur + 3 + size].to_vec();
        res.insert(key, value);
        cur += 3 + size;
    }

    Ok(res)
}

fn encode(obj: BTreeMap<u8, Vec<u8>>) -> Vec<u8> {
    let mut res = Vec::new();

    for (k, v) in obj {
        res.push(k);
        res.push(((v.len() >> 8) & 0xFF) as u8);
        res.push((v.len() & 0xFF) as u8);
        res.extend_from_slice(&v);
    }

    res.extend_from_slice(&[0, 0, 0]);
    res
}

/// Error response from the ABN Amro API
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    /// Human-readable error message
    pub message: Option<String>,
    /// Error type or code
    pub error: Option<String>,
    /// HTTP status code associated with the error
    pub status: Option<u16>,
}

const BASE: &str = "https://www.abnamro.nl";
const START: &str =
    "https://www.abnamro.nl/portalserver/mijn-abnamro/mijn-overzicht/overzicht/index.html";
const SERVICE_VERSION_HEADER: &str = "x-aab-serviceversion";
const SERVICE_VERSION: &str = "v3";
const USER_AGENT_STR: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
