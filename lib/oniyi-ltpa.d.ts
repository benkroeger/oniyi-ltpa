declare module 'oniyi-ltpa' {
  export interface Ltpa2Tools {
    getKeyfile: () => {
      version: string;
      creationDate: string;
      creationHost: string;
      realm: string;
      publicKey: string;
      des3Key: string;
      privateKey: string;
      privateKeyPEM: string;
    };
    decode: (token: string) => {
      body: Record<string, string>;
      // epoch milliseconds
      expires: string;
      signature: string;
    };
    decodeV1: (token: string) => {
      body: Record<string, string>;
      // epoch milliseconds
      expires: string;
      signature: string;
    };
    makeToken: (content: {
      body: Record<string, string>;
      expires: string | number;
    }) => string;
  }
  export const ltpa2Factory: (
    keyfilePath: string,
    keyfilePassword: string,
    callback: (error: Error | null | undefined, ltpa2Tools: Ltpa2Tools) => void,
  ) => void;
}
