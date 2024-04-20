const schemas = {
    opaque: {
        register: {
            init: {
                type: "object",
                properties: {
                    init: {
                        type: "array",
                        items: { type: "integer" },
                    },
                    username: { type: "string" },
                },
            },
            finish: {
                type: "object",
                properties: {
                    record: {
                        type: "array",
                        items: { type: "integer" },
                    },
                    username: { type: "string" },
                },
            },
        },
        auth: {
            init: {
                type: "object",
                properties: {
                    ke1: {
                        type: "array",
                        items: { type: "integer" },
                    },
                    username: { type: "string" },
                },
            },
            finish: {
                type: "object",
                properties: {
                    ke3: {
                        type: "array",
                        items: { type: "integer" },
                    },
                    username: { type: "string" },
                    session_key: {
                        type: "array",
                        items: { type: "integer" },
                    },
                },
            },
        },
    },
    owl: {
        register: {
            init: {
                type: "object",
                properties: {
                    username: { type: "string" },
                    data: {
                        type: "object",
                        properties: {
                            T: { type: "string" },
                            pi: { type: "string" },
                        },
                    },
                },
            },
        },
        auth: {
            init: {
                type: "object",
                properties: {
                    username: { type: "string" },
                    init: {
                        type: "object",
                        properties: {
                            X1: { type: "string" },
                            X2: { type: "string" },
                            PI1: {
                                type: "object",
                                properties: {
                                    h: { type: "string" },
                                    r: { type: "string" },
                                },
                            },
                            PI2: {
                                type: "object",
                                properties: {
                                    h: { type: "string" },
                                    r: { type: "string" },
                                },
                            },
                        },
                    },
                },
            },
            finish: {
                type: "object",
                properties: {
                    username: { type: "string" },
                    finish: {
                        type: "object",
                        properties: {
                            alpha: { type: "string" },
                            PIAlpha: {
                                type: "object",
                                properties: {
                                    h: { type: "string" },
                                    r: { type: "string" },
                                },
                            },
                            r: { type: "string" },
                        },
                    },
                    kc: { type: "string" },
                },
            },
        },
    },
};
export default schemas;
