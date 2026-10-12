declare module "@mariozechner/pi-ai" {
  export const createNativeJudge:
    | ((
        model: object,
        connection: {
          apiKey:
            | string
            | ((options?: { signal?: AbortSignal }) => Promise<string | undefined>);
          headers?: Record<string, string>;
        },
      ) => {
        judge(
          request: unknown,
          options?: { signal?: AbortSignal },
        ): Promise<unknown>;
      })
    | undefined;
}
