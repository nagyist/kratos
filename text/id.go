// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package text

// This file MUST not have any imports to modules that are not in the standard library.
// Otherwise, `make docs/cli` will fail.

type ID int

const (
	InfoSelfServiceLoginRoot                 ID = 1010000 + iota // 1010000
	InfoSelfServiceLogin                                         // 1010001
	InfoSelfServiceLoginWith                                     // 1010002
	InfoSelfServiceLoginReAuth                                   // 1010003
	InfoSelfServiceLoginMFA                                      // 1010004
	InfoSelfServiceLoginVerify                                   // 1010005
	InfoSelfServiceLoginTOTPLabel                                // 1010006
	InfoLoginLookupLabel                                         // 1010007
	InfoSelfServiceLoginWebAuthn                                 // 1010008
	InfoLoginTOTP                                                // 1010009
	InfoLoginLookup                                              // 1010010
	InfoSelfServiceLoginContinueWebAuthn                         // 1010011
	InfoSelfServiceLoginWebAuthnPasswordless                     // 1010012
	InfoSelfServiceLoginContinue                                 // 1010013
	InfoSelfServiceLoginCodeSent                                 // 1010014
	InfoSelfServiceLoginCode                                     // 1010015
	InfoSelfServiceLoginLink                                     // 1010016
	InfoSelfServiceLoginAndLink                                  // 1010017
	InfoSelfServiceLoginWithAndLink                              // 1010018
	InfoSelfServiceLoginCodeMFA                                  // 1010019
	InfoSelfServiceLoginCodeMFAHint                              // 1010020
	InfoSelfServiceLoginPasskey                                  // 1010021
	InfoSelfServiceLoginPassword                                 // 1010022
	InfoSelfServiceLoginAAL2CodeAddress                          // 1010023
)

const (
	InfoSelfServiceLogout ID = 1020000 + iota
)

const (
	InfoSelfServiceMFA ID = 1030000 + iota
)

const (
	InfoSelfServiceRegistrationRoot              ID = 1040000 + iota // 1040000
	InfoSelfServiceRegistration                                      // 1040001
	InfoSelfServiceRegistrationWith                                  // 1040002
	InfoSelfServiceRegistrationContinue                              // 1040003
	InfoSelfServiceRegistrationRegisterWebAuthn                      // 1040004
	InfoSelfServiceRegistrationEmailWithCodeSent                     // 1040005
	InfoSelfServiceRegistrationRegisterCode                          // 1040006
	InfoSelfServiceRegistrationRegisterPasskey                       // 1040007
	InfoSelfServiceRegistrationBack                                  // 1040008
	InfoSelfServiceRegistrationChooseCredentials                     // 1040009
)

const (
	InfoSelfServiceSettings ID = 1050000 + iota
	InfoSelfServiceSettingsUpdateSuccess
	InfoSelfServiceSettingsUpdateLinkOidc
	InfoSelfServiceSettingsUpdateUnlinkOidc
	InfoSelfServiceSettingsUpdateUnlinkTOTP
	InfoSelfServiceSettingsTOTPQRCode
	InfoSelfServiceSettingsTOTPSecret
	InfoSelfServiceSettingsRevealLookup
	InfoSelfServiceSettingsRegenerateLookup
	InfoSelfServiceSettingsLookupSecret
	InfoSelfServiceSettingsLookupSecretLabel
	InfoSelfServiceSettingsLookupConfirm
	InfoSelfServiceSettingsRegisterWebAuthn
	InfoSelfServiceSettingsRegisterWebAuthnDisplayName
	InfoSelfServiceSettingsLookupSecretUsed
	InfoSelfServiceSettingsLookupSecretList
	InfoSelfServiceSettingsDisableLookup
	InfoSelfServiceSettingsTOTPSecretLabel
	InfoSelfServiceSettingsRemoveWebAuthn
	InfoSelfServiceSettingsRegisterPasskey
	InfoSelfServiceSettingsRemovePasskey
)

const (
	InfoSelfServiceRecovery                          ID = 1060000 + iota // 1060000
	InfoSelfServiceRecoverySuccessful                                    // 1060001
	InfoSelfServiceRecoveryEmailSent                                     // 1060002
	InfoSelfServiceRecoveryEmailWithCodeSent                             // 1060003
	InfoSelfServiceRecoveryMessageMaskedWithCodeSent                     // 1060004
	InfoSelfServiceRecoveryAskForFullAddress                             // 1060005
	InfoSelfServiceRecoveryAskToChooseAddress                            // 1060006
	InfoSelfServiceRecoveryBack                                          // 1060007
)

const (
	InfoNodeLabel                       ID = 1070000 + iota // 1070000
	InfoNodeLabelInputPassword                              // 1070001
	InfoNodeLabelGenerated                                  // 1070002
	InfoNodeLabelSave                                       // 1070003
	InfoNodeLabelID                                         // 1070004
	InfoNodeLabelSubmit                                     // 1070005
	InfoNodeLabelVerifyOTP                                  // 1070006
	InfoNodeLabelEmail                                      // 1070007
	InfoNodeLabelResendOTP                                  // 1070008
	InfoNodeLabelContinue                                   // 1070009
	InfoNodeLabelRecoveryCode                               // 1070010
	InfoNodeLabelVerificationCode                           // 1070011
	InfoNodeLabelRegistrationCode                           // 1070012
	InfoNodeLabelLoginCode                                  // 1070013
	InfoNodeLabelLoginAndLinkCredential                     // 1070014
	InfoNodeLabelCaptcha                                    // 1070015
	InfoNodeLabelRecoveryAddress                            // 1070016
	InfoNodeLabelPhoneNumber                                // 1070017
)

const (
	InfoSelfServiceVerification                  ID = 1080000 + iota // 1080000
	InfoSelfServiceVerificationEmailSent                             // 1080001
	InfoSelfServiceVerificationSuccessful                            // 1080002
	InfoSelfServiceVerificationEmailWithCodeSent                     // 1080003
)

const (
	ErrorValidation ID = 4000000 + iota
	ErrorValidationGeneric
	ErrorValidationRequired
	ErrorValidationMinLength
	ErrorValidationInvalidFormat
	ErrorValidationPasswordPolicyViolationGeneric
	ErrorValidationInvalidCredentials
	ErrorValidationDuplicateCredentials
	ErrorValidationTOTPVerifierWrong
	ErrorValidationIdentifierMissing
	ErrorValidationAddressNotVerified
	ErrorValidationNoTOTPDevice
	ErrorValidationLookupAlreadyUsed
	ErrorValidationNoWebAuthnDevice
	ErrorValidationNoLookup
	ErrorValidationSuchNoWebAuthnUser
	ErrorValidationLookupInvalid
	ErrorValidationMaxLength
	ErrorValidationMinimum
	ErrorValidationExclusiveMinimum
	ErrorValidationMaximum
	ErrorValidationExclusiveMaximum
	ErrorValidationMultipleOf
	ErrorValidationMaxItems
	ErrorValidationMinItems
	ErrorValidationUniqueItems
	ErrorValidationWrongType
	ErrorValidationDuplicateCredentialsOnOIDCLink
	ErrorValidationDuplicateCredentialsWithHints
	ErrorValidationConst
	ErrorValidationConstGeneric
	ErrorValidationPasswordIdentifierTooSimilar
	ErrorValidationPasswordMinLength
	ErrorValidationPasswordMaxLength
	ErrorValidationPasswordTooManyBreaches
	ErrorValidationNoCodeUser
	ErrorValidationTraitsMismatch
	ErrorValidationAccountNotFound
	ErrorValidationCaptchaError
)

const (
	ErrorValidationLogin                            ID = 4010000 + iota // 4010000
	ErrorValidationLoginFlowExpired                                     // 4010001
	ErrorValidationLoginNoStrategyFound                                 // 4010002
	ErrorValidationRegistrationNoStrategyFound                          // 4010003
	ErrorValidationSettingsNoStrategyFound                              // 4010004
	ErrorValidationRecoveryNoStrategyFound                              // 4010005
	ErrorValidationVerificationNoStrategyFound                          // 4010006
	ErrorValidationLoginRetrySuccess                                    // 4010007
	ErrorValidationLoginCodeInvalidOrAlreadyUsed                        // 4010008
	ErrorValidationLoginLinkedCredentialsDoNotMatch                     // 4010009
	ErrorValidationLoginAddressUnknown                                  // 4010010
)

const (
	ErrorValidationRegistration                         ID = 4040000 + iota
	ErrorValidationRegistrationFlowExpired                 // 4040001
	ErrorValidateionRegistrationRetrySuccess               // 4040002
	ErrorValidationRegistrationCodeInvalidOrAlreadyUsed    // 4040003
)

const (
	ErrorValidationSettings ID = 4050000 + iota
	ErrorValidationSettingsFlowExpired
)

const (
	ErrorValidationRecovery                          ID = 4060000 + iota // 4060000
	ErrorValidationRecoveryRetrySuccess                                  // 4060001
	ErrorValidationRecoveryStateFailure                                  // 4060002
	ErrorValidationRecoveryMissingRecoveryToken                          // 4060003
	ErrorValidationRecoveryTokenInvalidOrAlreadyUsed                     // 4060004
	ErrorValidationRecoveryFlowExpired                                   // 4060005
	ErrorValidationRecoveryCodeInvalidOrAlreadyUsed                      // 4060006
)

const (
	ErrorValidationVerification                          ID = 4070000 + iota // 4070000
	ErrorValidationVerificationTokenInvalidOrAlreadyUsed                     // 4070001
	ErrorValidationVerificationRetrySuccess                                  // 4070002
	ErrorValidationVerificationStateFailure                                  // 4070003
	ErrorValidationVerificationMissingVerificationToken                      // 4070004
	ErrorValidationVerificationFlowExpired                                   // 4070005
	ErrorValidationVerificationCodeInvalidOrAlreadyUsed                      // 4070006
)

const (
	ErrorSystem ID = 5000000 + iota
	ErrorSystemGeneric
)
