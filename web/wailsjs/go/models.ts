export namespace desktop {
	
	export class BleEnrollResult {
	    status: string;
	    reason?: string;
	    deviceId?: string;
	    devicePublicKey?: string;
	    bundleDelivered: boolean;
	    envelopeBytes: number;
	    bundleBytes?: number;
	
	    static createFrom(source: any = {}) {
	        return new BleEnrollResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.status = source["status"];
	        this.reason = source["reason"];
	        this.deviceId = source["deviceId"];
	        this.devicePublicKey = source["devicePublicKey"];
	        this.bundleDelivered = source["bundleDelivered"];
	        this.envelopeBytes = source["envelopeBytes"];
	        this.bundleBytes = source["bundleBytes"];
	    }
	}
	export class C8YCredential {
	    id: string;
	    url?: string;
	    username?: string;
	    hasSecret: boolean;
	    updatedAt?: string;
	
	    static createFrom(source: any = {}) {
	        return new C8YCredential(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.url = source["url"];
	        this.username = source["username"];
	        this.hasSecret = source["hasSecret"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class RuntimeInfo {
	    mode: string;
	    token: string;
	    baseURL: string;
	    signingKey: string;
	    defaultSealRegex?: string;
	    configDir?: string;
	    configPath?: string;
	    adminTokenFile?: string;
	    signingKeyFile?: string;
	    ageKeyFile?: string;
	    profilesDir?: string;
	    firstRun?: boolean;
	    bootstrappedFiles?: string[];
	    capabilities: string[];
	
	    static createFrom(source: any = {}) {
	        return new RuntimeInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mode = source["mode"];
	        this.token = source["token"];
	        this.baseURL = source["baseURL"];
	        this.signingKey = source["signingKey"];
	        this.defaultSealRegex = source["defaultSealRegex"];
	        this.configDir = source["configDir"];
	        this.configPath = source["configPath"];
	        this.adminTokenFile = source["adminTokenFile"];
	        this.signingKeyFile = source["signingKeyFile"];
	        this.ageKeyFile = source["ageKeyFile"];
	        this.profilesDir = source["profilesDir"];
	        this.firstRun = source["firstRun"];
	        this.bootstrappedFiles = source["bootstrappedFiles"];
	        this.capabilities = source["capabilities"];
	    }
	}

}

export namespace options {
	
	export class SecondInstanceData {
	    Args: string[];
	    WorkingDirectory: string;
	
	    static createFrom(source: any = {}) {
	        return new SecondInstanceData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Args = source["Args"];
	        this.WorkingDirectory = source["WorkingDirectory"];
	    }
	}

}

