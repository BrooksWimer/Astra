import React from "react";
import { createNativeStackNavigator } from "@react-navigation/native-stack";
import { ConnectScreen } from "../screens/ConnectScreen";
import { DashboardScreen } from "../screens/DeviceListScreen";
import { DeviceDetailScreen } from "../screens/DeviceDetailScreen";

export type RootStackParamList = {
  Connect: undefined;
  Dashboard: undefined;
  DeviceDetail: { deviceId: string };
};

const Stack = createNativeStackNavigator<RootStackParamList>();

export function RootStack() {
  return (
    <Stack.Navigator
      initialRouteName="Dashboard"
      screenOptions={{ headerShown: false, animation: "slide_from_right" }}
    >
      <Stack.Screen name="Connect" component={ConnectScreen} />
      <Stack.Screen name="Dashboard" component={DashboardScreen} />
      <Stack.Screen name="DeviceDetail" component={DeviceDetailScreen} />
    </Stack.Navigator>
  );
}
