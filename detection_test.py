from fido2 import ctap
from fido2 import cbor
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialParameters
from fido2 import hid
from tools.configure import fatal, info, get_opensk_devices

from hashlib import sha256
import random

ES256_ALGORITHM = PublicKeyCredentialParameters("public-key", -7)
HYBRID_ALGORITHM = PublicKeyCredentialParameters("public-key", -65537)

def get_authenticator():
    devices = None
    while not devices:
        try:
            devices = get_opensk_devices(False)
        except Exception as e:  # pylint: disable=broad-except
            error(str(e))
            check_call(["nrfjprog", "--reset", "--family", "NRF52"],
                       stdout=DEVNULL,
                       stderr=STDOUT)
            sleep(0.1)
        return devices[0]

def main():
    authenticator = get_authenticator()
    key_params=[HYBRID_ALGORITHM, ES256_ALGORITHM]

    mitm_controlled_key_params = [ES256_ALGORITHM]
    mitm_controlled_iter = random.randint(0, 9)

    for i in range(0, 10):
        try:
            if i==mitm_controlled_iter:
                result = authenticator.make_credential(
                    client_data_hash=bytes(32),
                    rp=PublicKeyCredentialRpEntity(id="exapmle.com", name="Example"),
                    user=PublicKeyCredentialUserEntity(id=b"diana", name="Diana"),
                    key_params=mitm_controlled_key_params
                )
            else:
                result = authenticator.make_credential(
                    client_data_hash=bytes(32),
                    rp=PublicKeyCredentialRpEntity(id="exapmle.com", name="Example"),
                    user=PublicKeyCredentialUserEntity(id=b"diana", name="Diana"),
                    key_params=key_params
                )

            expected_hash = cbor.encode(key_params)
            m = sha256()
            m.update(result.cred_params.hash)
            actual_hash = m.digest()
            if expected_hash != actual_hash and i == mitm_controlled_iter:
                print("Successfully detected MitM attack during registration")
                print(f"    Expected hash: {expected_hash}")
                print(f"    Actual hash: {actual_hash}")
            elif expected_hash != actual_hash and i != mitm_controlled_iter:
                print("Falsly detected MitM attack during registration")
                print(f"    Expected hash: {expected_hash}")
                print(f"    Actual hash: {actual_hash}")
            elif expected_hash == actual_hash and i == mitm_controlled_iter:
                print("MitM attack succeeded undetected during registration")
                print(f"    Expected hash: {expected_hash}")
                print(f"    Actual hash: {actual_hash}")

        except ctap.CtapError as ex:
            message = "Failed to make a hybrid signature with OpenSK"
            if ex.code.value == ctap.CtapError.ERR.INVALID_COMMAND:
                error(f"{message} (unsupported command).")
            elif ex.code.value == ctap.CtapError.ERR.INVALID_PARAMETER:
                error(f"{message} (invalid parameter, maybe a wrong byte array size?).")
            elif ex.code.value == 0xF2:  # VENDOR_INTERNAL_ERROR
                error(f"{message} (internal conditions not met).")
            elif ex.code.value == 0xF3:  # VENDOR_HARDWARE_FAILURE
                error(f"{message} (internal hardware error).")
            else:
                error(f"{message} (unexpected error: {ex})")
        except Exception as e:  # pylint: disable=broad-except
            error(str(e))

if __name__ == "__main__":
    main()
