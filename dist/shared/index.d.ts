export type CanonicalJsonValue = null | boolean | number | string | CanonicalJsonValue[] | {
    [key: string]: CanonicalJsonValue;
};
export type PresenceProof = {
    algorithm: "ed25519";
    signer_public_key: string;
    payload_hash: string;
    signature: string;
    lat: number;
    lng: number;
    accuracy_m: number;
    timestamp_ms: number;
    nonce: string;
};
export type LocusObjectDraft = {
    schema_id: string;
    radius_m: number;
    payload: CanonicalJsonValue;
    creator_public_key: string;
    creator_signature: string;
};
type PresencePayload = Omit<PresenceProof, "algorithm" | "payload_hash" | "signature">;
type ObjectDraftPayload = Omit<LocusObjectDraft, "creator_signature">;
export declare function generateEd25519KeyPair(): Promise<{
    publicKey: string;
    privateKey: string;
}>;
export declare function signEd25519(payloadHash: string, privateKey: string): Promise<string>;
export declare function verifyEd25519(payloadHash: string, signatureBase64: string, publicKey: string): Promise<boolean>;
export declare function createPresencePayloadHash(payload: PresencePayload): Promise<string>;
export declare function createObjectDraftHash(payload: ObjectDraftPayload): Promise<string>;
export declare function verifyPresenceProof(presence: PresenceProof): Promise<boolean>;
export declare function verifyObjectDraftSignature(draft: LocusObjectDraft): Promise<boolean>;
export declare function cellIdFromLatLng(lat: number, lng: number, resolution: number): string;
export {};
