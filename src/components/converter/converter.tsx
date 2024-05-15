import { invoke } from "@tauri-apps/api";
import { RadioGroupProps, SelectProps } from "antd";
import { TextEncoding } from "../codec/codec";

export abstract class Converter<T> {
	async defaultConvert(
		privateKey: string,
		publicKey: string,
		from: T,
		to: T
	): Promise<string[]> {
		if (from === to) {
			return new Promise<string[]>((resovle, _) => {
				resovle([privateKey, publicKey]);
			});
		}
		return this.convert(privateKey, publicKey, from, to);
	}

	abstract convert(
		privateKey: string,
		publicKey: string,
		from: T,
		to: T
	): Promise<string[]>;
}

export type ConvertRef = {
	getTextEncoding: () => TextEncoding;
	setTextEncoding: (encoding: TextEncoding) => void;
};

export interface ConvertRadioProps<T> extends RadioGroupProps {
	converter: Converter<T>;
	getInputs: () => Record<string, string>;
	setInputs: (input: Record<string, string>) => void;
}

export interface ConvertSelectProps<T, E> extends SelectProps {
	converter: Converter<E>;
	getInputs: () => Record<string, unknown>;
	setInputs: (inputs: Record<string, unknown>) => void;
	value?: T;
	onChange?: (value: T) => void;
}

export enum CurveName {
	NIST_P256 = "nistp256",
	NIST_P384 = "nistp384",
	NIST_P521 = "nistp521",
	Secp256k1 = "secp256k1",
}

export enum Pkcs1Format {
	PKCS1_PEM = "pkcs1_pem",
	PKCS1_DER = "pkcs1_der",
}

export enum Sec1Format {
	SEC1_PEM = "sec1_pem",
	SEC1_DER = "sec1_der",
}

export enum Pkcs8Format {
	PKCS8_PEM = "pkcs8_pem",
	PKCS8_DER = "pkcs8_der",
}

export const rsaFormats = [
	{ value: Pkcs8Format.PKCS8_PEM, label: <span>pkcs8-pem</span> },
	{ value: Pkcs8Format.PKCS8_DER, label: <span>pkcs8-der</span> },
	{ value: Sec1Format.SEC1_PEM, label: <span>sec1-pem</span> },
	{ value: Sec1Format.SEC1_DER, label: <span>sec1-der</span> },
];

export const eccFormats = [
	{ value: Pkcs8Format.PKCS8_PEM, label: <span>pkcs8-pem</span> },
	{ value: Pkcs8Format.PKCS8_DER, label: <span>pkcs8-der</span> },
	{ value: Sec1Format.SEC1_PEM, label: <span>sec1-pem</span> },
	{ value: Sec1Format.SEC1_DER, label: <span>sec1-der</span> },
];

export enum Pkcs {
	Pkcs1 = "pkcs1",
	Pkcs8 = "pkcs8",
	Sec1 = "sec1",
}

export enum KeyFormat {
	Pem = "pem",
	Der = "der",
}

export class PkcsEncodingProps {
	pkcs: Pkcs;
	format: KeyFormat;
	encoding?: TextEncoding;

	constructor(pkcs: Pkcs, keyFormat: KeyFormat) {
		this.pkcs = pkcs;
		this.format = keyFormat;
	}

	setEncoding(encoding: TextEncoding): PkcsEncodingProps {
		this.encoding = encoding;
		return this;
	}
}

export const PkcsFormats: Record<PkcsFormat, PkcsEncodingProps> = {
	pkcs8_pem: new PkcsEncodingProps(Pkcs.Pkcs8, KeyFormat.Pem),
	pkcs8_der: new PkcsEncodingProps(Pkcs.Pkcs8, KeyFormat.Der),
	pkcs1_pem: new PkcsEncodingProps(Pkcs.Pkcs1, KeyFormat.Pem),
	pkcs1_der: new PkcsEncodingProps(Pkcs.Pkcs1, KeyFormat.Der),
	sec1_pem: new PkcsEncodingProps(Pkcs.Sec1, KeyFormat.Pem),
	sec1_der: new PkcsEncodingProps(Pkcs.Sec1, KeyFormat.Der),
};

export const RsaPkiEncoding = { ...Pkcs1Format, ...Pkcs8Format };
export type RsaPkiEncoding = typeof RsaPkiEncoding;

export type PkcsFormat = Pkcs8Format | Sec1Format | Pkcs1Format;
export type RsaFormat = Pkcs8Format | Pkcs1Format;
export type EccFromat = Pkcs8Format | Sec1Format;

export class RsaPkcsConverter extends Converter<PkcsEncodingProps> {
	async convert(
		privateKey: string,
		publicKey: string,
		from: PkcsEncodingProps,
		to: PkcsEncodingProps
	): Promise<string[]> {
		switch (true) {
			case from.pkcs === Pkcs.Pkcs8 && to.pkcs === Pkcs.Pkcs1:
			case from.pkcs === Pkcs.Pkcs1 && to.pkcs === Pkcs.Pkcs8:
			case from.pkcs === Pkcs.Pkcs8 && to.pkcs === Pkcs.Pkcs8:
			case from.pkcs === Pkcs.Pkcs1 && to.pkcs === Pkcs.Pkcs1:
				return await invoke<string[]>("rsa_transfer_key", {
					privateKey,
					publicKey,
					from,
					to,
				});
			default:
				throw new Error(
					`unsupported pkcs: ${from.pkcs} encoding: ${from.encoding} convert pkcs: ${to.pkcs} encoding: ${to.encoding}`
				);
		}
	}
}

export class EccPkcsConverter extends Converter<PkcsEncodingProps> {
	public curveName: CurveName = CurveName.NIST_P256;
	setCurveName(curveName: CurveName) {
		this.curveName = curveName;
	}
	async convert(
		privateKey: string,
		publicKey: string,
		from: PkcsEncodingProps,
		to: PkcsEncodingProps
	): Promise<string[]> {
		switch (true) {
			case from.pkcs === Pkcs.Pkcs8 && to.pkcs === Pkcs.Sec1:
			case from.pkcs === Pkcs.Sec1 && to.pkcs === Pkcs.Pkcs8:
			case from.pkcs === Pkcs.Pkcs8 && to.pkcs === Pkcs.Pkcs8:
			case from.pkcs === Pkcs.Sec1 && to.pkcs === Pkcs.Sec1:
				return await invoke<string[]>("ecc_transfer_key", {
					curveName: this.curveName,
					privateKey,
					publicKey,
					from,
					to,
				});
			default:
				throw new Error(
					`unsupported pkcs: ${from.pkcs} encoding: ${from.encoding} convert pkcs: ${to.pkcs} encoding: ${to.encoding}`
				);
		}
	}
}

export class RsaEncodingConverter extends Converter<PkcsEncodingProps> {
	async convert(
		privateKey: string,
		publicKey: string,
		from: PkcsEncodingProps,
		to: PkcsEncodingProps
	): Promise<string[]> {
		return await invoke<string[]>("rsa_transfer_key", {
			privateKey,
			publicKey,
			from,
			to,
		});
	}
}

export class EccEncodingConverter extends Converter<PkcsEncodingProps> {
	public curveName: CurveName = CurveName.NIST_P256;
	setCurveName(curveName: CurveName) {
		this.curveName = curveName;
	}
	async convert(
		privateKey: string,
		publicKey: string,
		from: PkcsEncodingProps,
		to: PkcsEncodingProps
	): Promise<string[]> {
		return await invoke<string[]>("ecc_transfer_key", {
			curveName: this.curveName,
			privateKey,
			publicKey,
			from,
			to,
		});
	}
}
export const rsaPkcsConverter = new RsaPkcsConverter();
export const eccPkcsConverter = new EccPkcsConverter();
export const rsaEncodingConverter = new RsaEncodingConverter();
export const eccEncodingConverter = new EccEncodingConverter();
