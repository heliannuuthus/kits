import { Card, Col, Flex, Row, Typography } from "antd";
import { createStyles } from "antd-style";
import { RefObject, useEffect, useRef, useState } from "react";
import { DefaultTextArea } from "../encryption/rsa";

const useStyles = createStyles(({ css }) => ({
	container: css`
		.ant-card {
			border-radius: 0;
			height: auto;
		}
		.ant-typography {
			font-weight: 500;
			margin-top: 0px;
			margin-bottom: 20px;
		}
		.ant-card-head {
			height: 31px;
			min-height: 31px;
			font-weight: 100;
		}
		.ant-card-body {
			padding: 20px;
		}
	`,
}));

const JWS = () => {
	const { styles } = useStyles();

	const resizeObserver = (ref: RefObject<HTMLDivElement>) => {
		const observer = new ResizeObserver(() => {
			setJwsHeight((pre) => {
				if (ref.current) {
					console.log(ref.current.scrollHeight);
					return ref.current.scrollHeight;
				}
				return pre;
			});
		});
		if (ref.current) {
			observer.observe(ref.current);
		}
		return observer;
	};
	const [jwsHeight, setJwsHeight] = useState<number>(0);

	const rightRef = useRef<HTMLDivElement>(null);

	useEffect(() => {
		const headerObserver = resizeObserver(rightRef);
		return () => {
			headerObserver.disconnect();
		};
	}, []);

	return (
		<Row
			style={{
				marginTop: 64,
			}}
			className={styles.container}
		>
			<Col span={11}>
				<Typography.Title level={3}>Encoded</Typography.Title>
			</Col>
			<Col offset={1} span={11}>
				<Typography.Title level={3}>Decoded</Typography.Title>
			</Col>
			<Col span={11}>
				<Card
					style={{
						height: jwsHeight ? `${jwsHeight}px` : "auto",
						resize: "none",
					}}
				>
					<DefaultTextArea variant="borderless"></DefaultTextArea>
				</Card>
			</Col>
			<Col offset={1} span={11}>
				<Flex vertical style={{ height: "auto" }} ref={rightRef}>
					<Card title="header">
						<DefaultTextArea
							autoSize={true}
							variant="borderless"
						></DefaultTextArea>
					</Card>
					<Card title="payload">
						<DefaultTextArea
							autoSize={true}
							variant="borderless"
						></DefaultTextArea>
					</Card>
					<Card title="signature"></Card>
				</Flex>
			</Col>
		</Row>
	);
};

export default JWS;
