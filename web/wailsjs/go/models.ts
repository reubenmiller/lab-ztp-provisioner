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
	export class RuntimeInfo {
	    mode: string;
	    token: string;
	    baseURL: string;
	    signingKey: string;
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
	        this.capabilities = source["capabilities"];
	    }
	}

}

