use common_enums::enums;
use common_utils::types::StringMinorUnit;
use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors;
use masking::Secret;
use serde::{Deserialize, Serialize};
use chrono;

use crate::types::{RefundsResponseRouterData, ResponseRouterData};

//TODO: Fill the struct with respective fields
#[derive(Debug,Serialize)]
pub struct BkashRouterData<T> {
    pub amount: StringMinorUnit, // The type of amount that a connector accepts, for example, String, i64, f64, etc.
    pub router_data: T,
}

impl<T> From<(StringMinorUnit, T)> for BkashRouterData<T> {
    fn from((amount, router_data): (StringMinorUnit, T)) -> Self {
        //Todo :  use utils to convert the amount to the type of amount that a connector accepts
        Self {
            amount,
            router_data,
        }
    }
}

// bKash Create Payment Request
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct BkashPaymentsRequest {
    pub mode: String,
    #[serde(rename = "payerReference")]
    pub payer_reference: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: String,
    #[serde(rename = "merchantAssociationInfo")]
    pub merchant_association_info: Option<String>,
    pub amount: String,
    pub currency: String,
    pub intent: String,
    #[serde(rename = "merchantInvoiceNumber")]
    pub merchant_invoice_number: String,
}

impl TryFrom<&BkashRouterData<&PaymentsAuthorizeRouterData>> for BkashPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &BkashRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self, Self::Error> {
        // For bKash, we need to create a payment request that will redirect to bKash's payment page
        // The actual payment will be completed on bKash's side
        let payer_reference = "add_later".to_string();

        let merchant_invoice_number = item.router_data.request.metadata.clone()
            .and_then(|meta| {
                meta.get("merchant_invoice_number")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| format!("INV_{}", chrono::Utc::now().timestamp()));

        Ok(Self {
            mode: "0011".to_string(), // Checkout mode
            payer_reference,
            callback_url: item.router_data.request.callback_url.clone()
                .unwrap_or_else(|| "https://example.com/callback".to_string()),
            merchant_association_info: None,
            amount: item.amount.to_string(),
            currency: item.router_data.request.currency.to_string(),
            intent: "sale".to_string(),
            merchant_invoice_number,
        })
    }
}

//TODO: Fill the struct with respective fields
// Auth Struct
pub struct BkashAuthType {
    pub(super) app_key: Secret<String>,
    pub(super) app_secret: Secret<String>,
    pub(super) username: Secret<String>,
    pub(super) password: Secret<String>,

}

impl TryFrom<&ConnectorAuthType> for BkashAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2
            } => Ok(Self {
                app_key: api_key.to_owned(),
                app_secret:api_secret.to_owned(),
                username:key1.to_owned(),
                password:key2.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}
// PaymentsResponse
// bKash Payment Status
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BkashPaymentStatus {
    Initiated,
    Completed,
    Failed,
    Cancelled,
    #[default]
    Processing,
}

impl From<BkashPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: BkashPaymentStatus) -> Self {
        match item {
            BkashPaymentStatus::Completed => Self::Charged,
            BkashPaymentStatus::Failed | BkashPaymentStatus::Cancelled => Self::Failure,
            BkashPaymentStatus::Initiated | BkashPaymentStatus::Processing => Self::Authorizing,
        }
    }
}

// bKash Create Payment Response
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BkashPaymentsResponse {
    #[serde(rename = "paymentID")]
    pub payment_id: Option<String>,
    #[serde(rename = "bkashURL")]
    pub bkash_url: Option<String>,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(rename = "successCallbackURL")]
    pub success_callback_url: Option<String>,
    #[serde(rename = "failureCallbackURL")]
    pub failure_callback_url: Option<String>,
    #[serde(rename = "cancelledCallbackURL")]
    pub cancelled_callback_url: Option<String>,
    pub amount: Option<String>,
    pub intent: Option<String>,
    pub currency: Option<String>,
    #[serde(rename = "paymentCreateTime")]
    pub payment_create_time: Option<String>,
    #[serde(rename = "transactionStatus")]
    pub transaction_status: Option<String>,
    #[serde(rename = "merchantInvoiceNumber")]
    pub merchant_invoice_number: Option<String>,
    #[serde(rename = "statusCode")]
    pub status_code: Option<String>,
    #[serde(rename = "statusMessage")]
    pub status_message: Option<String>,
}

impl<F, T> TryFrom<ResponseRouterData<F, BkashPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, BkashPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let status = if let Some(status_code) = &item.response.status_code {
            match status_code.as_str() {
                "0000" => {
                    if let Some(transaction_status) = &item.response.transaction_status {
                        match transaction_status.as_str() {
                            "Completed" => common_enums::AttemptStatus::Charged,
                            "Initiated" => common_enums::AttemptStatus::Authorizing,
                            _ => common_enums::AttemptStatus::Authorizing,
                        }
                    } else {
                        common_enums::AttemptStatus::Authorizing
                    }
                }
                _ => common_enums::AttemptStatus::Failure,
            }
        } else {
            common_enums::AttemptStatus::Authorizing
        };

        let resource_id = item.response.payment_id
            .as_ref()
            .map(|id| ResponseId::ConnectorTransactionId(id.clone()))
            .unwrap_or_else(|| ResponseId::NoResponseId);

        // For bKash, we need to redirect to their payment page
        // let redirection_data = item.response.bkash_url
        //     .as_ref()
        //     .map(|url| Box::new(Some(RedirectionData {
        //         status: common_enums::IntentStatus::RequiresCustomerAction,
        //         redirect_to: Some(url.clone()),
        //         return_url: item.response.callback_url.clone(),
        //         payment_method_data: None,
        //         connector_metadata: None,
        //         mandate_reference: None,
        //         payment_method_type: None,
        //         payment_method: None,
        //         payment_method_issuer: None,
        //         payment_experience: None,
        //         connector_request_reference_id: None,
        //         message: None,
        //         gateway_merchant_id: None,
        //         gateway_name: None,
        //         gateway_merchant_id_2: None,
        //         gateway_name_2: None,
        //         gateway_merchant_id_3: None,
        //         gateway_name_3: None,
        //         gateway_merchant_id_4: None,
        //         gateway_name_4: None,
        //         gateway_merchant_id_5: None,
        //         gateway_name_5: None,
        //         gateway_merchant_id_6: None,
        //         gateway_name_6: None,
        //         gateway_merchant_id_7: None,
        //         gateway_name_7: None,
        //         gateway_merchant_id_8: None,
        //         gateway_name_8: None,
        //         gateway_merchant_id_9: None,
        //         gateway_name_9: None,
        //         gateway_merchant_id_10: None,
        //         gateway_name_10: None,
        //     })));

        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

// bKash Refund Request
#[derive(Default, Debug, Serialize)]
pub struct BkashRefundRequest {
    pub payment_id: String,
    pub trx_id: String,
    pub refund_amount: String,
    pub sku: Option<String>,
    pub reason: Option<String>,
}

impl<F> TryFrom<&BkashRouterData<&RefundsRouterData<F>>> for BkashRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &BkashRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        // Extract payment_id and trx_id from connector_metadata
        let (payment_id, trx_id) = if let Some(metadata) = &item.router_data.request.connector_metadata {
            let payment_id = metadata.get("payment_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| errors::ConnectorError::MissingRequiredField {
                    field_name: "payment_id",
                })?;

            let trx_id = metadata.get("trx_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| errors::ConnectorError::MissingRequiredField {
                    field_name: "trx_id",
                })?;

            (payment_id.to_string(), trx_id.to_string())
        } else {
            return Err(errors::ConnectorError::MissingRequiredField {
                field_name: "connector_metadata",
            }.into());
        };

        Ok(Self {
            payment_id,
            trx_id,
            refund_amount: item.amount.to_string(),
            sku: None,
            reason: Some("Customer request".to_string()),
        })
    }
}

// Type definition for Refund Response

#[allow(dead_code)]
#[derive(Debug, Copy, Serialize, Default, Deserialize, Clone)]
pub enum RefundStatus {
    Completed,
    Failed,
    #[default]
    Processing,
}

impl From<RefundStatus> for enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Completed => Self::Success,
            RefundStatus::Failed => Self::Failure,
            RefundStatus::Processing => Self::Pending,
        }
    }
}

// bKash Refund Response
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    #[serde(rename = "originalTrxId")]
    pub original_trx_id: String,
    #[serde(rename = "refundTrxId")]
    pub refund_trx_id: String,
    #[serde(rename = "refundTransactionStatus")]
    pub refund_transaction_status: String,
    #[serde(rename = "originalTrxAmount")]
    pub original_trx_amount: String,
    #[serde(rename = "refundAmount")]
    pub refund_amount: String,
    pub currency: String,
    #[serde(rename = "completedTime")]
    pub completed_time: String,
    pub sku: Option<String>,
    pub reason: Option<String>,
}

impl TryFrom<RefundsResponseRouterData<Execute, RefundResponse>> for RefundsRouterData<Execute> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        let refund_status = match item.response.refund_transaction_status.as_str() {
            "Completed" => enums::RefundStatus::Success,
            "Failed" => enums::RefundStatus::Failure,
            _ => enums::RefundStatus::Pending,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.refund_trx_id.clone(),
                refund_status,
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, RefundResponse>> for RefundsRouterData<RSync> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<RSync, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        let refund_status = match item.response.refund_transaction_status.as_str() {
            "Completed" => enums::RefundStatus::Success,
            "Failed" => enums::RefundStatus::Failure,
            _ => enums::RefundStatus::Pending,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.refund_trx_id.clone(),
                refund_status,
            }),
            ..item.data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct BkashGrantTokenRequest {
    pub app_key: Secret<String>,
    pub app_secret: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BkashGrantTokenResponse {
    pub token_type: String,
    pub id_token: Secret<String>,
    pub expires_in: i64, // Change to i64 as it's a numeric value
    pub refresh_token: Option<Secret<String>>, // Optional if not always present
    // You might want to add statusCode and statusMessage if present in error cases
}

// This struct will represent the access token stored by Hyperswitch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BkashAccessToken {
    pub id_token: Secret<String>,
    pub expires_in: i64, // When the token expires (seconds from now)
    pub created_at: i64, // When the token was created (Unix timestamp)
    pub app_key: Secret<String>, // We need app_key for subsequent requests
}

// Define the request struct for Create Payment
#[derive(Debug, Serialize)]
pub struct BkashCreatePaymentRequest {
    pub mode: String,
    #[serde(rename = "payerReference")]
    pub payer_reference: Option<String>,
    #[serde(rename = "callbackURL")]
    pub callback_url: String,
    #[serde(rename = "merchantAssociationInfo")]
    pub merchant_association_info: Option<String>,
    pub amount: String,
    pub currency: String,
    pub intent: String,
    #[serde(rename = "merchantInvoiceNumber")]
    pub merchant_invoice_number: String,
}

// Define the response struct for Create Payment
#[derive(Debug, Deserialize, Serialize)]
pub struct BkashCreatePaymentResponse {
    #[serde(rename = "statusCode")]
    pub status_code: String,
    #[serde(rename = "statusMessage")]
    pub status_message: String,
    #[serde(rename = "paymentID")]
    pub payment_id: Option<String>,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(rename = "successCallbackURL")]
    pub success_callback_url: Option<String>,
    #[serde(rename = "failureCallbackURL")]
    pub failure_callback_url: Option<String>,
    #[serde(rename = "cancelledCallbackURL")]
    pub cancelled_callback_url: Option<String>,
    pub amount: Option<String>,
    pub intent: Option<String>,
    pub currency: Option<String>,
    #[serde(rename = "paymentCreateTime")]
    pub payment_create_time: Option<String>,
    #[serde(rename = "transactionStatus")]
    pub transaction_status: Option<String>,
    #[serde(rename = "merchantInvoiceNumber")]
    pub merchant_invoice_number: Option<String>,
}


// bKash Error Response
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct BkashErrorResponse {
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
    #[serde(rename = "internalCode")]
    pub internal_code: Option<String>,
    #[serde(rename = "externalCode")]
    pub external_code: Option<String>,
    #[serde(rename = "errorMessageEn")]
    pub error_message_en: Option<String>,
    #[serde(rename = "errorMessageBn")]
    pub error_message_bn: Option<String>,
}

