use hex;
use jni::objects::{GlobalRef, JClass, JObject};
use jni::sys::jbyteArray;
use jni::JNIEnv;
use log::{trace, info, warn};
use log::LevelFilter;
use log4rs;
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Root},
};
use serde::Deserialize;
use std::error;
use std::fs::{self};

use emvpt::*;

static mut ENV: Option<JNIEnv<'static>> = None;
static mut CALLBACK: Option<GlobalRef> = None;
static mut APDU_RESPONSE: Vec<u8> = Vec::new();

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_sendApduResponse(
    env: JNIEnv,
    _class: JClass,
    response_apdu: jbyteArray,
) {
    unsafe {
        APDU_RESPONSE.clear();
        APDU_RESPONSE.extend_from_slice(&env.convert_byte_array(response_apdu).unwrap()[..]);
        trace!("RESPONSE: {:02X?}", APDU_RESPONSE);
    }
}

struct JavaSmartCardConnection {}

impl ApduInterface for JavaSmartCardConnection {
    fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, ()> {
        trace!("CALLING {:02X?}", apdu);

        let mut output: Vec<u8> = Vec::new();

        unsafe {
            let request_apdu = ENV.as_ref().unwrap().byte_array_from_slice(apdu).unwrap();
            ENV.as_ref()
                .unwrap()
                .call_method(
                    CALLBACK.as_ref().unwrap(),
                    "sendApduRequest",
                    "([B)V",
                    &[request_apdu.into()],
                )
                .unwrap();

            output.extend_from_slice(&APDU_RESPONSE[..]);
        }

        Ok(output)
    }
}

fn init_logging() -> Result<(), Box<dyn error::Error>> {
    let stdout: ConsoleAppender = ConsoleAppender::builder().build();
    let config = log4rs::config::Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Debug));

    if let Err(e) = log4rs::init_config(config.unwrap()) {
        return Err(Box::new(e));
    }

    Ok(())
}

#[derive(Deserialize, Clone)]
struct ApduRequestResponse {
    req: String,
    res: String,
}

impl ApduRequestResponse {
    fn to_raw_vec(s: &String) -> Vec<u8> {
        hex::decode(s.replace(" ", "")).unwrap()
    }

    fn execute_setup_apdus(connection: &mut EmvConnection, setup_file: &str) -> Result<(), String> {
        // Setup the app ICC data
        let card_setup_data: Vec<ApduRequestResponse> =
            serde_yaml::from_str(&fs::read_to_string(setup_file).unwrap()).unwrap();
        for apdu in card_setup_data {
            let request = ApduRequestResponse::to_raw_vec(&apdu.req);
            let response = ApduRequestResponse::to_raw_vec(&apdu.res);

            let (response_trailer, _) = connection.send_apdu(&request);
            if &response_trailer[..] != &response[..] {
                return Err(format!(
                    "Response not what expected! setup_file:{}, req:{:02X?}, expected:{:02X?}, actual:{:02X?}",
                    setup_file,
                    &request[..],
                    &response[..],
                    &response_trailer[..]
                ));
            }
        }

        Ok(())
    }
}

fn pin_entry() -> Result<String, ()> {
    Ok("1234".to_string())
}

fn start_transaction(connection: &mut EmvConnection) -> Result<(), ()> {
    // force transaction date as 24.07.2020
    connection.add_tag("9A", b"\x20\x07\x24".to_vec());

    // force unpreditable number
    connection.add_tag("9F37", b"\x01\x23\x45\x67".to_vec());
    connection.settings.terminal.use_random = false;

    // force issuer authentication data
    connection.add_tag("91", b"\x12\x34\x56\x78\x12\x34\x56\x78".to_vec());

    // transaction amount 0,01 EUR
    connection.add_tag("9F02", b"\x00\x00\x00\x00\x00\x01".to_vec());

    Ok(())
}

fn setup_connection(connection: &mut EmvConnection) -> Result<(), ()> {
    connection.contactless = false;
    connection.pse_application_select_callback = None;
    connection.pin_callback = Some(&pin_entry);
    connection.amount_callback = None;
    connection.start_transaction_callback = Some(&start_transaction);

    Ok(())
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_entryPoint(
    env: JNIEnv<'static>,
    _class: JClass,
    callback: JObject,
) {
    trace!("Simulator entry point called!");

    init_logging().unwrap();

    unsafe {
        // Setup JVM and callback points to Simulator class

        ENV = Some(env);

        let _jvm = ENV.as_ref().unwrap().get_java_vm().unwrap();

        CALLBACK = Some(ENV.as_ref().unwrap().new_global_ref(callback).unwrap());

        let mut connection = EmvConnection::new("../config/settings.yaml").unwrap();
        let smart_card_connection = JavaSmartCardConnection {};
        connection.interface = Some(&smart_card_connection);
        setup_connection(&mut connection).unwrap();

        // Setup the PSE ICC data
        ApduRequestResponse::execute_setup_apdus(
            &mut connection,
            "../config/card_setup_pse_apdus.yaml",
        )
        .unwrap();

        let applications = connection
            .handle_select_payment_system_environment()
            .unwrap();

        // Setup the app ICC data
        ApduRequestResponse::execute_setup_apdus(
            &mut connection,
            "../config/card_setup_app_apdus.yaml",
        )
        .unwrap();

        let application = &applications[0];
        connection
            .handle_select_payment_application(application)
            .unwrap();

        connection.start_transaction(&application).unwrap();

        connection.process_settings().unwrap();

        let search_tag = b"\x9f\x36";
        connection.handle_get_data(&search_tag[..]).unwrap();

        connection.handle_card_verification_methods().unwrap();

        connection.handle_terminal_risk_management().unwrap();

        connection.handle_offline_data_authentication().unwrap();

        connection.handle_terminal_action_analysis().unwrap();

        if let CryptogramType::AuthorisationRequestCryptogram =
            connection.handle_1st_generate_ac().unwrap()
        {
            connection.handle_issuer_authentication_data().unwrap();
            connection.handle_2nd_generate_ac().unwrap();
        }

        // Consume logs that the card gathered
        ApduRequestResponse::execute_setup_apdus(
            &mut connection,
            "../config/card_log_consume_apdus.yaml",
        )
        .unwrap();
    }
}

// ============================================================
// Contactless Mastercard Kernel 2 test entry point
// ============================================================

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_ContactlessSimulatorTest_sendApduResponse(
    env: JNIEnv,
    _class: JClass,
    response_apdu: jbyteArray,
) {
    unsafe {
        APDU_RESPONSE.clear();
        APDU_RESPONSE.extend_from_slice(&env.convert_byte_array(response_apdu).unwrap()[..]);
        trace!("CL RESPONSE: {:02X?}", APDU_RESPONSE);
    }
}

fn pse_application_select_contactless(applications: &Vec<EmvApplication>) -> Result<EmvApplication, ()> {
    // Auto-select first application (for automated testing)
    if applications.is_empty() {
        warn!("No applications found in PPSE");
        return Err(());
    }
    info!("Auto-selecting application: AID={:02X?}, label={:?}",
        applications[0].aid,
        String::from_utf8_lossy(&applications[0].label));
    Ok(applications[0].clone())
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_ContactlessSimulatorTest_entryPointContactless(
    env: JNIEnv<'static>,
    _class: JClass,
    callback: JObject,
) {
    let _ = init_logging();
    info!("Contactless Kernel 2 simulator entry point called!");

    unsafe {
        ENV = Some(env);
        let _jvm = ENV.as_ref().unwrap().get_java_vm().unwrap();
        CALLBACK = Some(ENV.as_ref().unwrap().new_global_ref(callback).unwrap());

        info!("JNI env and callback set up OK");

        let mut connection = EmvConnection::new("../config/settings_contactless.yaml").unwrap();
        info!("EmvConnection created OK, contactless_kernels={}", connection.settings.contactless_kernels.is_some());
        let smart_card_connection = JavaSmartCardConnection {};
        connection.interface = Some(&smart_card_connection);
        connection.contactless = true;
        connection.pse_application_select_callback = Some(&pse_application_select_contactless);
        connection.pin_callback = Some(&pin_entry);
        connection.settings.terminal.use_random = false;

        // Setup PPSE data on the card
        ApduRequestResponse::execute_setup_apdus(
            &mut connection,
            "../config/card_setup_ppse_apdus.yaml",
        )
        .unwrap();

        // Select PPSE and get application list
        let application = connection.select_payment_application().unwrap();
        info!("Selected application: AID={:02X?}", application.aid);

        // Setup the contactless MC payment app data
        if let Err(e) = ApduRequestResponse::execute_setup_apdus(
            &mut connection,
            "../config/card_setup_mc_contactless_apdus.yaml",
        ) {
            panic!("MC contactless setup failed: {}", e);
        }

        // Process settings (sets default tags, date, time, unpredictable number)
        connection.process_settings().unwrap();

        // Force deterministic values for reproducible tests
        connection.add_tag("9A", b"\x26\x04\x13".to_vec());
        connection.add_tag("9F37", b"\xDE\xAD\xBE\xEF".to_vec());
        connection.add_tag("9F02", b"\x00\x00\x00\x00\x10\x00".to_vec()); // $10.00

        // Run the contactless transaction through Kernel 2
        info!("=== Starting Mastercard Contactless Kernel 2 transaction ===");

        match connection.handle_contactless_transaction(&application) {
            Ok(outcome) => {
                info!("Contactless transaction outcome: {}", outcome);

                use emvpt::contactless::OutcomeType;
                match outcome.outcome {
                    OutcomeType::Approved => {
                        info!("=== KERNEL 2 TEST: APPROVED (offline) ===");
                    }
                    OutcomeType::OnlineRequest => {
                        info!("=== KERNEL 2 TEST: ONLINE REQUEST (ARQC) ===");
                    }
                    OutcomeType::Declined => {
                        warn!("=== KERNEL 2 TEST: DECLINED ===");
                    }
                    other => {
                        warn!("=== KERNEL 2 TEST: {:?} ===", other);
                    }
                }
            }
            Err(e) => {
                panic!("Contactless transaction failed: {}", e);
            }
        }

        info!("=== Mastercard Contactless Kernel 2 test complete ===");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
